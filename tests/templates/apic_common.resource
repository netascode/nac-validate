*** Settings ***
Library   pabot.PabotLib
Library   RequestsLibrary
Library   JSONLibrary
Library   Collections
Library   String

*** Variables ***
${login_json}   {"aaaUser" : {"attributes" : {"name" : "%{ACI_USERNAME}", "pwd" : "%{ACI_PASSWORD}"}}}

*** Keywords ***
Get APIC Token
    Create Session   login   %{ACI_URL}
    ${response}=   POST On Session   login   /api/aaaLogin.json   data=${login_json}
    ${r_token}=   Get Value From Json   ${response.json()}   $..token
    Set Parallel Value For Key   apic_token   ${r_token[0]}
    Set Suite Variable   ${apic_token}   ${r_token[0]}

Login APIC
    Wait Until Keyword Succeeds   5x   1 s   Acquire Lock   login
    ${apic_token}=   Get Parallel Value For Key   apic_token
    Run Keyword If   "${apic_token}"=="${EMPTY}"   Get APIC Token
    Release Lock   login
    Create Session   apic   %{ACI_URL}   headers={"Cookie": "APIC-cookie=${apic_token}"}

Should Be Equal Value Json String
    [Arguments]    ${json}    ${json_path}   ${value}=${EMPTY}
    ${r_value}=   Get Value From Json   ${json}   ${json_path}
    Run Keyword If   "${value}" != "${EMPTY}"   Should Be Equal As Strings   ${r_value}[0]   ${value}
