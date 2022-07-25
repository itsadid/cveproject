import json
import re
import weakref
import csv

import pandas as pd
import numpy as np
from consts import Consts

from src.utils import Utils


class CVEExtract(object):
    @staticmethod
    def df_basic_analysis(df, regex_vendor):
        cve_year = []
        cve_vendor = []
        cves = []

        cves_per_vendor_count = 0
        cves_total_count = len(df)
        for cve_index in range(cves_total_count):
            cve_name = df['Name'].iloc[cve_index]
            year_extract = Utils.search(r"\-\d+\-", cve_name)[0]
            year = int(year_extract[1:-1])
            cve_description = df['Description'].iloc[cve_index]
            guessed_vendors = Utils.search(regex_vendor, cve_description)
            if guessed_vendors:
                cve_vendor.append(list(set(guessed_vendors)))
                cves.append(cve_name)
                cve_year.append(year)
                cves_per_vendor_count += 1

        print('Found ', cves_per_vendor_count, regex_vendor, 'matches')
        return cves, cve_vendor, cve_year, cves_total_count

    # Extract CVEs by Vendor, Year, Version and Bug Class
    @staticmethod
    def df_bug_analysis(df, index, regex_vendor, major_bug_classes):
        cve_bug = []

        # index
        for cve_index in range(index):
            cve_name = df['Name'].iloc[cve_index]
            cve_description = df['Description'].iloc[cve_index]
            guessed_vendors = Utils.search(regex_vendor, cve_description)
            if guessed_vendors:
                bugs_per_cve = []
                for major in major_bug_classes:
                    for minor in major_bug_classes[major]:
                        bug_search = Utils.search(minor, cve_description)
                        if bug_search:
                            bugs_per_cve.append(major)
                            break
                cve_bug.append(bugs_per_cve)
                if len(bugs_per_cve) == 0:
                    print('No bug detected', cve_name, '\n', 'Description cve: ', cve_description)
                print('-' * 20)
        return cve_bug

    @staticmethod
    def df_exploit_analysis(df, index, regex_vendor, exploit_type):
        cve_primitives = []

        # index
        for cve_index in range(index):
            cve_name = df['Name'].iloc[cve_index]
            cve_description = df['Description'].iloc[cve_index]
            guessed_vendors = Utils.search(regex_vendor, cve_description)
            if guessed_vendors:
                exploit_per_cve = []
                for exploit in exploit_type:
                    for primitive in exploit_type[exploit]:
                        exploit_search = Utils.search(primitive, cve_description)
                        if exploit_search:
                            exploit_per_cve.append(exploit)
                            break
                cve_primitives.append(exploit_per_cve)
                if len(exploit_per_cve) == 0:
                    print('No exploit detected', cve_name, '\n', 'Description cve: ', cve_description)
                print('-' * 20)
        return cve_primitives

    # Extract Operating System type
    @staticmethod
    def df_os_analysis(df, index, regex_vendor, apple_operating_systems):
        cve_os = []

        for cve_index in range(index):
            cve_name = df['Name'].iloc[cve_index]
            cve_description = df['Description'].iloc[cve_index]
            guessed_vendors = Utils.search(regex_vendor, cve_description)
            if guessed_vendors:
                os_per_cve = []
                for software in apple_operating_systems:
                    for os_type in apple_operating_systems[software]:
                        os_search = Utils.search(os_type, cve_description)
                        if os_search:
                            os_per_cve.append(software)
                            break
                cve_os.append(os_per_cve)
                if len(os_per_cve) == 0:
                    print('No OS detected', cve_name, '\n', 'Description cve: ', cve_description)
                print('-' * 20)
        return cve_os

    @staticmethod
    def df_version_analysis(df, index, regex_vendor, regex_queries):
        cve_version = []

        for cve_index in range(index):
            cve_name = df['Name'].iloc[cve_index]
            cve_description = df['Description'].iloc[cve_index]
            guessed_vendors = Utils.search(regex_vendor, cve_description)
            if guessed_vendors:
                version_per_cve = []
                for query in regex_queries:
                    # print(query)
                    version_search = Utils.search(query, cve_description)
                    # print(version_search)
                    if version_search:
                        for find in version_search:
                            version_per_cve.append(find)
                    # if len(version_per_cve) == 0:
                    #     print('No Version detected', cve_name, '\n', 'Description cve: ', cve_description)
                    #     print('-' * 20)
                cve_version.append(version_per_cve)

        return cve_version

    # Extract the relevant versions per CVE

    # new DF for the Extracted data
    @staticmethod
    def create_csv_file(csv_path, cves, cve_vendor, cve_year, cve_bug, cve_primitives, cve_os, cve_version):
        df = pd.DataFrame({'Cve Id': cves,
                           'Vendor': cve_vendor,
                           'Year': cve_year,
                           'Bug Class': cve_bug,
                           'Exploit Primitive': cve_primitives,
                           'OS/Product': cve_os,
                           'Affected Versions': cve_version})

        new_csv = df.to_csv(csv_path, mode='a', index=False, header=False)
        # column_names = ["CVE", "Year", "Vendor", "OS", "Version", "Bug Class"]
        # new_df = pd.DataFrame(columns=column_names)
        print(new_csv)
        return new_csv

    # def create_csv(cves, cve_vendor, cve_year, index, cve_bug, cve_primitives, cve_os, cve_version):
    # with open('/home/superx64/work/python_projects/csv_trial.csv', 'a') as outcsv:
    #     writer = csv.writer(outcsv, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
    #     writer.writerow(['Cve Id', 'Vendor', 'Year', 'Bug Class', 'Exploit Primitive', 'OS/Product', 'Affected Versions'])
    #     for item in cves:
    #         writer.([item[0], item[1], item[2]])

    @staticmethod
    def vendor_cve_extractor(df, regex_vendor, bug_classes, exploits, vendor_os, version):
        cves, cve_vendor, cve_year, index = CVEExtract.df_basic_analysis(df, regex_vendor)
        cve_bug = CVEExtract.df_bug_analysis(df, index, regex_vendor, bug_classes)
        cve_primitives = CVEExtract.df_exploit_analysis(df, index, regex_vendor, exploits)
        cve_os = CVEExtract.df_os_analysis(df, index, regex_vendor, vendor_os)
        cve_version = CVEExtract.df_version_analysis(df, index, regex_vendor, version)
        print('-' * 20)

        for i in range(len(cves)):
            print('cve          : ', cves[i])
            print('cve vendor   : ', cve_vendor[i])
            print('cve year   : ', cve_year[i])
            print('cve OS   : ', cve_os[i])
            print('cve OS versions   : ', cve_version[i])
            print('cve bug class      : ', cve_bug[i])
            print('cve exploit primitive   : ', cve_primitives[i])
            print('-' * 20)

        return cves, cve_vendor, cve_year, cve_bug, cve_primitives, cve_os, cve_version

    @staticmethod
    def run():
        print('start')

        # Import CVE Database
        # TODO: resp = requests.get('https://cve.mitre.org/data/downloads/allitems.csv') and save the file
        data = Utils.import_csv_table(Consts.FILE_NAME_CVE_DB_01)
        cve_df = Utils.table_selection(data)

        # Import Bug Classes
        major_bug_classes = Utils.get_cve_dictionary()['bug class']

        # Import exploit's primitives
        exploit_type = Utils.get_cve_dictionary()["exploit primitives"]

        # Import Apple's os
        apple_operating_systems = Utils.get_cve_dictionary()["apple os"]

        # Google's Products
        google_products = Utils.get_cve_dictionary()["Google Products"]

        # Samsung's Products
        samsung_products = Utils.get_cve_dictionary()["samsung products"]

        # import regex queries
        re_query = Utils.get_cve_dictionary()["regex queries"]

        # Count of CVE Values
        print('Total CVEs: ', len(cve_df))

        # Extract CVEs by Vendor, Year, Version and Bug Class
        regex_vendor_apple = '[Aa][Pp][Pp][Ll][Ee][.,:\s]'
        regex_vendor_samsung = '[Ss][Aa][Mm][Ss][Uu][Nn][Gg][.,:\s]'
        regex_vendor_google = '[Gg][Oo][Oo][Gg][Ll][Ee][.,:\s]'

        # Samsung SVE
        # sve_search = search(r'SVE-\d+-\d+', cve_description)

        # regex for version
        filled_version_regex = Utils.json_to_regex(apple_operating_systems, re_query)

        # vendor exctractor
        cves, cve_vendor, cve_year, cve_bug, cve_primitives, cve_os, cve_version = CVEExtract.vendor_cve_extractor(
            cve_df,
            regex_vendor_apple,
            major_bug_classes,
            exploit_type,
            apple_operating_systems,
            filled_version_regex)
        # vendor_cve_extractor(cve_df, regex_vendor_samsung, major_bug_classes, exploit_type, samsung_products, filled_version_regex)
        # vendor_cve_extractor(cve_df, regex_vendor_google, major_bug_classes, exploit_type, google_products, filled_version_regex)

        final = CVEExtract.create_csv_file(Consts.FILE_NAME_ANALYZED_DATA_CVE_OUTPUT, cves, cve_vendor, cve_year,
                                           cve_bug,
                                           cve_primitives, cve_os, cve_version)
        print(final)
