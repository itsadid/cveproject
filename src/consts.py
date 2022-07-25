class Consts:
    FILE_NAME_CVE_DICTIONARY_JSON = '/home/superx64/work/cveproject/misc/cve_dictionary.json'
    FILE_NAME_CVE_DB_01 = '/home/superx64/work/cveproject/misc/allitems.csv'
    FILE_NAME_ANALYZED_DATA_CVE_OUTPUT = '/home/superx64/work/cveproject/out/cve_analyzed_output.csv'
    FILE_NAME_CVE_SEVERITY_JSON = '/home/superx64/work/cveproject/misc/cve_severity_dictionary.json'
    FILE_NAME_CVE_MEDIUM_SEVERITY_JSON = '/home/superx64/work/cveproject/misc/cve_medium_severity_dicionary.json'
    FILE_NAME_CVE_LOW_SEVERITY_JSON = '/home/superx64/work/cveproject/misc/cve_low_severity_dicionary.json'
    FILE_NAME_CVE_CRITICAL_SEVERITY_JSON = '/home/superx64/work/cveproject/misc/cve_critical_severity_dicionary.json'
    URL_PATH_CVE_SEVERITY_JSON = ['https://services.nvd.nist.gov/rest/json/cves/1.0?cvssV2Severity=LOW',
                                  'https://services.nvd.nist.gov/rest/json/cves/1.0?cvssV2Severity=MEDIUM',
                                  'https://services.nvd.nist.gov/rest/json/cves/1.0?cvssV2Severity=HIGH',
                                  'https://services.nvd.nist.gov/rest/json/cves/1.0?cvssV3Severity=CRITICAL']
