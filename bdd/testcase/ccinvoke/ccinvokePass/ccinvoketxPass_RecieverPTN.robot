*** Settings ***
Library           RequestsLibrary
Library           Collections
Resource          ../../utilKwd/normalKwd.txt
Resource          ../../utilKwd/utilDefined.txt
Resource          ../../utilKwd/behaveKwd.txt

*** Variables ***
${host}           http://localhost:8545/
${geneAdd}        P1CwGYGSjWSaJrysHAjAWtDyFSsbcYwoULv
${recieverAdd}    P1MdMxNVaKZYdBBFB8Fszt8Bki1AEmRRSxw
${contractId}     PCGTta3M4t3yXu8uRgkKvaWd2d8DREThG43
${result_code}    [a-z0-9]{64}
${tokenId}        QA003
${tokenDecimal}    1
${tokenAmount}    25000
${poundage}       1
${amount}         2000
${gain}           2000

*** Test Cases ***
Ccinvoke RecieverPTN
    import library    /usr/lib/python2.7/decimal.py
    ${PTN1}    ${result}    normalGetBalance    ${recieverAdd}
    normalCcinvokePass    ${result_code}    ${tokenId}    ${tokenDecimal}    ${tokenAmount}    ${amount}    1
    ${gain1}    countRecieverPTN    ${gain}
    ${PTNGAIN}    Evaluate    decimal.Decimal('${PTN1}')+decimal.Decimal('${gain1}')    decimal
    sleep    4
    ${PTN2}    ${result}    normalGetBalance    ${recieverAdd}
    Should Be Equal As Numbers    ${PTNGAIN}    ${PTN2}