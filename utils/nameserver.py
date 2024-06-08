import csv
import re
import os


class NsLookup:
    @staticmethod
    def get_name_by_as_number(as_number: int) -> list | None:
        """Filters rows in csv by AS Number and returns unique NS names"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, "nameservers.csv")

        with open(file_path, mode="r") as file:
            csv_reader = csv.DictReader(file)
            results_found = list()
            for row in csv_reader:
                if row["as_number"] == str(as_number):
                    results_found.append(row["name"])

            results_found = list(set([r for r in results_found if r]))

        return results_found

    @staticmethod
    def extract_as_number(s: str) -> int | None:
        """Extracts the AS number from a string"""
        match = re.search(r"AS(\d+)", s)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def get_name_by_as_string(s: str) -> list | None:
        """
        Extracts AS number from a string
        Looks up the number from CSV file and returns NS names
        """
        as_number = NsLookup.extract_as_number(s)
        if as_number:
            return NsLookup.get_name_by_as_number(as_number)
        return None
