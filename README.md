# CIS-Benchmarks-Python
Python script to enable or disable CIS Benchmarks at the project level.

## Script Overview
This python script makes it possible to suppress CIS Benchmarks at the project level instead of only at the organization level. Due to how the API is set up, we are unable to pass an authentication token in the request. Instead, you will need to first login to the platform for the intended tenent, then the script will extract the cookie for that session to use for the request.

## Prerequisites
  
  -  You must be logged in to the platform on one of the following browsers:
      - Google Chrome
      - Firefox
      - Opera
      - Chromium
  - You must have Python 3.9 installed
  - You must have the libraries from the requirements.txt file installed

## How the script works
  1) Arguements are specified on the command line and passed into the program (see usage)
  2) Cookie is extracted from the specified browse
  3) Rules are checked to make sure that they are a valid option (see usage)
  4) A payload with the ruleset is generated
  5) A post request is made to the `/api/v1/complianceConfig` endpoint with the platform specified as a paramter
        - ex: `https://example.lacework.net/api/v1/complianceConfig?CLOUD_PROVIDER=GCP`
  6) A return code and the return message are printed to the terminal
        - example of successful message: `SUCCESS - 200`

## Usage
To run the script after cloning the repo, issue the following command:

`python3 main.py --browser [chrome|firefox|opera|chromium] --tenent example --action [enable|disable] --rules [all_gcp|all_azure|gcp_cis_rules|gcp_cis12_rules] --platform [gcp|azure] --project "project_name" --comment "example comment"`

For example, if I was:

- Logged into my instance in Chrome
- My tenent's name was 'example'
- I wanted to enable all of the GCP rules 
- I wanted to do this for my project "my-cool-project"

I could issue this command:

`python3 main.py --browser chrome --tenent example --action enable --rules all_gcp --platform gcp --project "my-cool-project" --comment "Enabling all CIS benchmarks for my project"`

## Things to note
- There are both an "--org" and "--resource-name flags but these are not currently used. In the future, these could let you specify disabling rules for just one org or just one resource
