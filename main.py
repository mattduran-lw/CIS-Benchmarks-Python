import requests
import re
import json
import browser_cookie3
import argparse


def main():
    """main function:
    Actions taken in here:
        - Arguement parser generated
        - Cookie extracted from browser
        - Rules are validated
        - Payload is generated
        - Request is made to API endpoint
    """
    args = generate_parser()
    if (args.action.lower() == "enable") or (args.action.lower() == "disable"):
        cookie = get_cookie(args.tenent, args.browser)
        # Uncomment below for testing payload without the need for a request
        # cookie = "Bypass for test"
        if args.browser is None or cookie is None:
            return
        rules_list = validate_rules(args.platform, args.rules, args.action.lower())
        if rules_list is None:
            return
        # TODO: Allow for org and resource name as well, currently set to default "*"
        if args.project:
            payload = build_payload(rules_list, args.action, args.comment, args.project)
        else:
            payload = build_payload(rules_list, args.action, args.comment)
        response = make_request(args.tenent, args.platform, payload, cookie)
    else:
        print("Invalid action -- should be enable or disable")
        print("Action given: " + args.action.lower())
    return


def generate_parser():
    """generate_parser()

    Parses the command line arguements given at runtime

    Arguments:
        --browser: What browser is currently logged into the platform (required)
        --tenent: What the tenent is for the platform (required)
        --action: What action to take on the rules; enable or disable (required)
        --project: The project name that you'd like to enable or disable the rules for (required)
        --rules: What rules to enable or disable (required)
        --platform: The platform that the customer is using -- azure or gcp (required)
        --org: Not currently used, the org that you would like to modify rules for
        --resource-name: Not currently used, specify suppression rules for a given resource
        --comment: Why you are enabling or disabling rules (required)

    Returns:
        ArgumentParser: https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Enable or disable CIS Benchmark rules on an Azure or GCP tenant"
    )
    parser.add_argument(
        "--browser",
        metavar="browser",
        type=str,
        required=True,
        help="The browser that you have logged in with. Possible commands are 'chrome', 'firefox', 'opera', 'chromium'",
    )
    parser.add_argument(
        "--tenent",
        metavar="tenent",
        type=str,
        required=True,
        help="The tenant that you have logged into -- example.lacework.net would be example.",
    )
    parser.add_argument(
        "--action",
        metavar="action",
        type=str,
        required=True,
        help="The action that you would like to complete. Possible commands are 'enable' or 'disable'",
    )
    parser.add_argument(
        "--project",
        metavar="project",
        type=str,
        required=True,
        help="The project name to enable or disable rules on.",
    )
    parser.add_argument(
        "--rules",
        metavar="rules",
        required=True,
        help="The rules to take an action on. Possible commands are 'gcp_all', 'azure_all', 'gcp_cis_rules', 'gcp_cis12_rules'",
    )
    parser.add_argument(
        "--platform",
        metavar="platform",
        type=str,
        required=True,
        help="The platform you are on. Possible commands are 'gcp' or 'azure'",
    )
    parser.add_argument(
        "--org", metavar="org", type=str, help="Lacework Organization for your account"
    )
    parser.add_argument(
        "--resource-name",
        metavar="resource-name",
        type=str,
        help="Resource name to specify",
    )
    parser.add_argument(
        "--comment",
        metavar="comment",
        type=str,
        required=True,
        help="Comment as to why action was taken -- should be wrapped in quotes.",
    )
    return parser.parse_args()


def get_cookie(tenent, browser):
    """get_cookie()
    Requires the browser_cookie3 library -- will extract a cookie from one
    of the specified browsers below. Currently works with Google Chrome, Firefox,
    Opera, and Chromium based browsers. The user will be prompted for their
    machine password to okay this.

    Args:
        tenent (str): The tenent in the lacework.net url -- used to determine the domain
        browser (str): What browser the user is using

    Returns:
        CookieJar: A CookieJar object which should only hold a cookie for the tenent url if it exists
    """
    domain = "%s.lacework.net" % tenent
    # TODO: Need to validate that the cookiejar object is not empty when a cookie is not found.
    if browser.lower() == "chrome":
        cookie_jar = browser_cookie3.chrome(domain_name=domain)
    elif browser.lower() == "firefox":
        cookie_jar = browser_cookie3.firefox(domain_name=domain)
    elif browser.lower() == "opera":
        cookie_jar = browser_cookie3.opera(domain_name=domain)
    elif browser.lower() == "chromium":
        cookie_jar = browser_cookie3.chromium(domain_name=domain)
    else:
        print("Browser not recognized, exiting program")
        return None
    return cookie_jar


def build_payload(
    rules,
    action,
    comment,
    project_id="*",
    org_id="*",
    resource_name="*",
):
    """build_payload()

    Constructs the payload for the post request.

    Args:
        rules (dict): The rule set to take an action on
        action (str): What action to take, needs to be specified for each rule in the payload
        comment (str): The comment that will be attached to the suppression rule
        project_id (str, optional): What project to specify the rule for. Defaults to "*".
        org_id (str, optional): Not currently used -- specifies the suppression rule for a given org. Defaults to "*".
        resource_name (str, optional): Not currently used -- specifies the suppression rule for a given resource. Defaults to "*".

    Returns:
        str: Returns a JSON string of the payload
    """
    payload = {
        "lastUpdate": {"SUPP_CFG_GUID": "", "USER_GUID": ""},
        "recommendationSuppressionConfigs": {},
        "props": {},
    }
    act = "false"
    if action == "enable":
        act = "true"
    for rule in rules:
        payload["recommendationSuppressionConfigs"][rule] = {
            "enabled": act,
            "suppressionConditions": [
                {
                    "organizationIds": [org_id],
                    "projectIds": [project_id],
                    "resourceNames": [resource_name],
                    "comments": comment,
                }
            ],
        }
    payload = json.dumps(payload)
    return payload


def make_request(tenent, platform, payload, cookie):
    """make_request()

    Makes the post request to the API endpoint

    Args:
        tenent (str): What tenent the account is on -- used to generate URL
        platform (str): What platform the account is using -- azure or gcp. Used to generate the URl
        payload (str): JSON string for which rules to modify
        cookie (CookieJar object): The cookie extracted from the browser -- used in request

    Returns:
        None: Returns nothing
    """
    post_url = "https://%s.lacework.net/api/v1/complianceConfig?CLOUD_PROVIDER=%s" % (
        tenent,
        platform.upper(),
    )
    # The API requires both the Session ID (SID) and the XSRF Token (XSRF-TOKEN) to be
    # included in the header (see headers variable below). In testing, it didn't seem to
    # require the actual cookie in the request itself, just the header, but it is included
    # for good measure.
    session_id = re.search(
        "(?<=\=)(.*?)(?=\ )", str(cookie._cookies["lwcs.lacework.net"]["/"]["SID"])
    )
    session_id = session_id.group()
    xsrf_token = re.search(
        "(?<=\=)(.*?)(?=\ )",
        str(cookie._cookies["lwcs.lacework.net"]["/"]["XSRF-TOKEN"]),
    )
    xsrf_token = xsrf_token.group()
    headers = {
        "X-XSRF-TOKEN": xsrf_token,
        "Cookie": "SID=" + session_id,
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    r = requests.post(post_url, data=payload, cookies=cookie, headers=headers)
    response_message = json.loads(r.text)
    response_message = response_message["message"]
    response_message = response_message + " - " + str(r.status_code)
    print(response_message)
    return None


def validate_rules(platform, rules, action):
    """validate_rules()
    Determines which rules to take action on. All rules are stored in the rules/ folder
    at the root of this program. These rules are JSON files which were gathered from the
    lacework CLI.

    Args:
        platform (str): Which platform the user is on -- azure or gcp
        rules (str): Which ruleset to take action on
        action (str): What to do -- enable or disable

    Returns:
        dict: A dictionary object of all the rules and what action to take
    """
    if rules == "all_gcp" and platform.lower() == "gcp":
        with open("rules/gcp_cis_rules.json", "r") as file:
            temp_dict = json.load(file)
        with open("rules/gcp_cis12_rules.json", "r") as file:
            temp_dict.update(json.load(file))
        with open("rules/gcp_k8s_rules.json", "r") as file:
            temp_dict.update(json.load(file))
        temp_dict = {i: action for i in temp_dict}
    elif rules == "all_azure" and platform.lower() == "azure":
        with open("rules/azure_cis_rules.json") as file:
            temp_dict = json.load(file)
            temp_dict = {i: action for i in temp_dict}
    elif rules == "disable_gcp_cis" and platform.lower() == "gcp":
        with open("rules/gcp_cis_rules.json") as file:
            temp_dict = json.load(file)
            temp_dict = {i: action for i in temp_dict}
    elif rules == "disable_gcp_cis12" and platform.lower() == "gcp":
        with open("rules/gcp_cis12_rules.json") as file:
            temp_dict = json.load(file)
            temp_dict = {i: action for i in temp_dict}
    else:
        print("Incorrect rules flag or platform")
        print("Platform given: " + platform.lower())
        print("Rules flag given: " + rules.lower())
        return None
    return temp_dict


if __name__ == "__main__":
    main()
