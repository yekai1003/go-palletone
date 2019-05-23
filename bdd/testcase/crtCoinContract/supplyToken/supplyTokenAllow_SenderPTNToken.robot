*** Settings ***
Default Tags      nomal
Library           ../../utilFunc/createToken.py
Resource          ../../utilKwd/utilVariables.txt
Resource          ../../utilKwd/normalKwd.txt
Resource          ../../utilKwd/utilDefined.txt
Resource          ../../utilKwd/behaveKwd.txt

*** Variables ***
${preTokenId}     QA030

*** Test Cases ***
Feature: Vote Contract- Create token
    [Documentation]    Scenario: Verify Sender's PTN
    ${geneAdd}    Given CcinvokePass normal
    ${PTN1}    ${key}    ${coinToken1}    And Request getbalance before create token    ${geneAdd}
    ${ret}    When Create token of vote contract    ${geneAdd}
    ${GAIN}    And Calculate gain of recieverAdd
    ${PTN2}    ${tokenGAIN}    And Request getbalance after create token    ${geneAdd}    ${key}    ${GAIN}
    Then Assert gain of reciever    ${PTN1}    ${PTN2}    ${tokenGAIN}    ${GAIN}

*** Keywords ***
CcinvokePass normal
    ${geneAdd}    getGeneAdd    ${host}
    Set Suite Variable    ${geneAdd}    ${geneAdd}
    I_set_CcinvokePass_params_to_Normal    ${commonResultCode}    ${preTokenId}    ${tokenDecimal}    ${tokenAmount}    ${geneAdd}    ${PTNAmount}
    ...    ${PTNPoundage}
    sleep    2
    [Return]    ${geneAdd}

Request getbalance before create token
    [Arguments]    ${geneAdd}
    #${PTN1}    ${result1}    normalGetBalance    ${geneAdd}
    ${result1}    getBalance    ${geneAdd}
    sleep    4
    ${key}    getTokenId    ${preTokenId}    ${result1}
    sleep    2
    ${PTN1}    Get From Dictionary    ${result1}    PTN
    sleep    1
    ${coinToken1}    Get From Dictionary    ${result1}    ${key}
    [Return]    ${PTN1}    ${key}    ${coinToken1}

Create token of vote contract
    [Arguments]    ${geneAdd}
    ${ccTokenList}    Create List    ${supplyTokenMethod}    ${preTokenId}    ${supplyTokenAmount}
    ${ccList}    Create List    ${geneAdd}    ${recieverAdd}    ${PTNAmount}    ${PTNPoundage}    ${transferContractId}
    ...    ${ccTokenList}    ${pwd}    ${duration}    ${EMPTY}
    ${resp}    setPostRequest    ${host}    ${invokePsMethod}    ${ccList}
    log    ${resp.content}
    Should Contain    ${resp.content}['jsonrpc']    "2.0"    msg="jsonrpc:failed"
    Should Contain    ${resp.content}['id']    1    msg="id:failed"
    ${ret}    Should Match Regexp    ${resp.content}['result']    ${commonResultCode}    msg="result:does't match Result expression"
    [Return]    ${ret}

Calculate gain of recieverAdd
    ${invokeGain}    Evaluate    int(${PTNAmount})+int(${PTNPoundage})
    ${GAIN}    countRecieverPTN    ${invokeGain}
    sleep    3
    [Return]    ${GAIN}

Request getbalance after create token
    [Arguments]    ${geneAdd}    ${key}    ${GAIN}
    ${result2}    getBalance    ${geneAdd}
    sleep    4
    ${coinToken2}    Get From Dictionary    ${result2}    ${key}
    sleep    2
    ${PTN2}    Get From Dictionary    ${result2}    PTN
    sleep    1
    ${tokenGAIN}    Evaluate    float(${coinToken2})-float(${coinToken1})
    [Return]    ${PTN2}    ${tokenGAIN}

Assert gain of reciever
    [Arguments]    ${PTN1}    ${PTN2}    ${tokenGAIN}    ${GAIN}
    ${PTNGAIN}    Evaluate    decimal.Decimal('${PTN1}')-decimal.Decimal('${GAIN}')    decimal
    ${supplyTokenAmount}    Evaluate    ${supplyTokenAmount}*(10**-${tokenDecimal})
    Should Be Equal As Numbers    ${PTN2}    ${PTNGAIN}
    Should Be Equal As Numbers    ${supplyTokenAmount}    ${tokenGAIN}
