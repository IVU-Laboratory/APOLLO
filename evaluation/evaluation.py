import preprocessor
import url_enricher
import llm_prompter
import os
import pandas as pd
from dotenv import load_dotenv
import csv
import time


# gpt-4-1106-preview
# No URL
# End index legit = 1726
# End index phishing = 3230

# With URL
# End index legit = 735
# End index phishing = 2750

START_INDEX = 0
END_INDEX = START_INDEX + 800
ENRICH_URL = [False]
QUANTILE = 100


def main():
    load_dotenv(os.path.join("..", ".env"))
    llm_prompter.set_api_key()  # Statically set the API key for OpenAI
    fieldnames = ["mail_id", "label", "prob", "true_label"]

    # Get already classified emails
    url_enriched_file = os.path.join('results', 'url_enriched_' + str(QUANTILE) + '.csv')
    if os.path.exists(url_enriched_file):
        y_results_url = pd.read_csv(url_enriched_file, names=fieldnames)
    else:
        open(url_enriched_file, 'a')  # create empty file
        y_results_url = pd.DataFrame(columns=fieldnames)

    url_no_enriched_file = os.path.join('results', 'no_url_enriched.csv')
    if os.path.exists(url_no_enriched_file):
        y_results_no_url = pd.read_csv(url_no_enriched_file, names=fieldnames)
    else:
        open(url_no_enriched_file, 'a')  # create empty file
        y_results_no_url = pd.DataFrame(columns=fieldnames)

    ## Load emails
    emails_df = pd.DataFrame()
    print("Loading emails...")
    for file_name in ["legit.csv", "phishing.csv"]:
        df = pd.read_csv(os.path.join('datasets', file_name), sep=",")
        emails_df = pd.concat([emails_df, df])

    # Get only emails in the specified range
    emails_df = emails_df.iloc[START_INDEX:END_INDEX]

    print("Classifying emails...")
    for enrich_url in ENRICH_URL:
        print("Enrich URL = " + ("True" if enrich_url else "False"))
        results = y_results_url if enrich_url else y_results_no_url  # get the correct dataframe (url enriched or not)
        for i in range(0, len(emails_df)):
            mail = emails_df.iloc[i]
            if (results["mail_id"] == mail["mail_id"]).any():  # check if email was already processed
                continue
            print(f"- Processing email {str(mail['mail_id'])} (index {START_INDEX + i})")
            # Get additional information about URLs in the email
            mail_urls = [] if len(mail["urls"]) == 0 else mail["urls"].split(" ")  # explode the string into a list
            if enrich_url:
                if len(mail_urls) == 0:  # Then the result is already stored in the no_url counterpart
                    # print([d for d in y_results_no_url if d['mail_id'] == mail_id])
                    print("No URL, skipping email...")
                    continue
                else:
                    # Call remote API to gather online URL information
                    # url_to_analyze = mail_urls[0]  # for now, we take the first URL
                    # print("-- Analyzing URL: " + url_to_analyze)
                    url_info = url_enricher.get_dummy_values(QUANTILE, mail["url_location"], mail["label"])  # url_enricher.get_url_info(url_to_analyze)
            else:
                url_info = None

            # Call GPT-4 for email phishing classification (automatic feature detection)
            # print("-- Classifying with GPT:")
            retry_counter = 3
            while True:
                y_label, y_prob = llm_prompter.classify_email_minimal(mail, url_info)
                if y_label == "Invalid format":
                    if retry_counter > 0:
                        retry_counter -= 1
                    else:
                        break
                elif y_label is None or y_prob is None:  # then there's an error in the response
                    print("Waiting 60 seconds before retrying...")
                    time.sleep(60)  # wait for 60 seconds
                    print("Retrying...")
                else:
                    break
            result = {"mail_id": mail["mail_id"], "label": y_label, "prob": y_prob, "true_label": str(mail["label"])}
            print(f"{result['mail_id']},{result['label']},{result['prob']},{result['true_label']}")
            # append result to file
            file_to_open = url_enriched_file if enrich_url else url_no_enriched_file
            with open(file_to_open, 'a') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(result)
        print("\n\n####\n\n")


if __name__ == "__main__":
    main()


"""
def add_missing_records_to_no_url_enriched_file():
    # Read the CSV files into pandas DataFrames
    no_url_df = pd.read_csv("no_url_enriched.csv")
    url_df = pd.read_csv("url_enriched.csv")

    # Find mail_ids present in no_url_df but missing in url_df
    missing_mail_ids = set(no_url_df['mail_id']) - set(url_df['mail_id'])

    # Filter rows from no_url_df where mail_id is in missing_mail_ids
    filtered_rows = no_url_df[no_url_df['mail_id'].isin(missing_mail_ids)]

    # Append the filtered rows to url_df and write to a new file url_enriched.csv
    url_df = url_df.append(filtered_rows)

    # Write the updated DataFrame to a new CSV file
    url_df.to_csv("url_enriched.csv", index=False)
"""

