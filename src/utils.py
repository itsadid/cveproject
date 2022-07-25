import json
import pandas as pd
import re
import requests

from src.consts import Consts


class Utils(object):

    @staticmethod
    def get_cve_dictionary():
        with open(Consts.FILE_NAME_CVE_DICTIONARY_JSON, "r") as f:
            content = f.read()
        cve_analysis_dictionary = json.loads(content)
        return cve_analysis_dictionary

    # Importing CSV into df
    @staticmethod
    def import_csv_table(csv_path):
        col_names = ["Name", "Status", "Description", "References", "Phase", "Votes", "Comments"]
        data = pd.read_csv(csv_path, names=col_names, encoding='latin-1', dtype={'Comments': str})
        return data

    # Display only relevant data
    @staticmethod
    def table_selection(table):
        selected_rows = table.iloc[10:]
        return selected_rows

    # regex analysis for df data
    @staticmethod
    def search(pattern, description):
        matches = re.findall(pattern, description, re.IGNORECASE)
        return matches

    @staticmethod
    def json_to_regex(major_os_list, regex_queries):
        queries = []
        for major in major_os_list:
            for minor in major_os_list[major]:
                os = minor
                for query in regex_queries:
                    filled_re = query.format(FILL_ME=os)
                    queries.append(filled_re)
        return queries

    @staticmethod
    def get_content_from_url(url):
        response = requests.get(url=url)
        if response.status_code != 200:
            raise Exception('error occurred during get')
        content = response.content
        return content

    @staticmethod
    def cve_json_analysis(json_file_urls):
        for url in json_file_urls:
            data = Utils.get_content_from_url(url)
            with open(Consts.FILE_NAME_CVE_SEVERITY_JSON, 'wb') as f:
                f.write(data)
        # print(data)

        json_files = Utils.cve_json_analysis(Consts.URL_PATH_CVE_SEVERITY_JSON)
        print(json_files)
