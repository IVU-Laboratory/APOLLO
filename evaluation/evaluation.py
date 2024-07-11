import re
import url_enricher
import llm_prompter
import os
import pandas as pd
from dotenv import load_dotenv
import json
from sklearn.metrics import precision_score, recall_score, accuracy_score, f1_score, log_loss, roc_auc_score, brier_score_loss


# gpt-4-1106-preview
# No URL
# End index legit = 1726
# End index phishing = 3230

# With URL
# End index legit = 735
# End index phishing = 2750

# Set ENRICH_URL to True to create a batch of requests that include URL Info
ENRICH_URL = False
QUANTILE = 0
FALSE_POSITIVES = True

fieldnames = ["mail_id", "label", "prob", "true_label"]

evaluations = ["noURL", "URL_Q=100", "URL_Q=75", "URL_Q=50", "URL_Q=25", "URL_Q=0"]
batch_model = ""  # this is updated from the llm_prompter module


def main():
    # get the emails from phishing.csv and legit.csv
    emails_df = load_emails(["legit.csv", "phishing.csv"])
    # Initialize Open AI parameters
    load_dotenv(os.path.join("..", ".env"))
    llm_prompter.initialize_openAI()  # Statically set the API key for OpenAI
    batch_model = llm_prompter.get_batch_model()

    input_command = None
    while input_command != "0":
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Evaluation set to URL_ENRICHER = {'true' if ENRICH_URL else 'false'}, QUANTILE = {QUANTILE}, model = {batch_model}.")
        print("1. Generate batches\n2. Launch individual batch\n3. Launch ALL batches\n4. Retrieve pending results\n5. Save results to csv file\n6. Compute metrics\n0. Exit")
        input_command = input("Insert your choice (0-6): ")
        while input_command not in ["1", "2", "3", "4", "5", "6", "0"]:
            input_command = input("Insert a valid command (0-6): ")
        if input_command == "1":  # generate
            generate_batches_choice(emails_df)
        if input_command == "2":  # launch individual batch
            launch_batch_choice()
        if input_command == "3":  # launch ALL batches
            launch_all_batches_choice()
        if input_command == "4":  # Retrieve results
            retrieve_results_choice()
        if input_command == "5":  # Retrieve results
            produce_output_file_choice()
        if input_command == "6":  # Compute metrics
            compute_metrics_choice()
    print("Bye!\n")


def generate_batches_choice(emails_df):
    retry = True
    while retry:  # Batch length input
        batch_length = input("Insert batch length (default 50): ")
        if batch_length == "":
            batch_length = 50
        try:
            batch_length = int(batch_length)
            if batch_length > 0:
                retry = False
            else:
                print("Please enter a number > 0")
        except ValueError:
            print("Please enter a valid number")
    # The number of batches will be = length of the dataset / batch_length
    n_batches = len(emails_df) // batch_length
    # Generate the batches of batch_length emails each
    for i in range(n_batches):
        start_index = i * batch_length
        end_index = start_index + batch_length
        if ENRICH_URL:
            file_name = f"requests_URL_Q={str(QUANTILE)}_{start_index}-{end_index}.jsonl"
        else:
            file_name = f"requests_noURL_{start_index}-{end_index}.jsonl"
        # Create the request only if we don't have the results yet and if it wasn't already generated
        if not os.path.exists(os.path.join("batches", "results", file_name)) \
                and not os.path.exists(os.path.join("batches", "requests", file_name)):
            # Create a jsonl file with the batch requests for OpenAI
            batch_df = emails_df[start_index:end_index]
            llm_prompter.generate_batch_requests_file(batch_df, file_name)


def launch_batch_choice():
    # Print the jsonl files in the batches/requests folder for user selection
    request_files = os.listdir(os.path.join("batches", "requests"))

    # Sort the files according to their name (0-50, 50-100, 100-150, etc.)
    def extract_number(filename):  # Define a function to extract the numeric value from the filename
        match = re.search(r'_(\d+)-', filename)
        return int(match.group(1)) if match else float('inf')

    # Sort the files using the numeric value as the key
    request_files = sorted(request_files, key=extract_number)

    print(f" \nSelect the request batch to launch:")
    i = 1
    # Print the sorted filenames
    for request_file in request_files:
        print(str(i) + ")" + request_file)
        i += 1

    # Acquire user selection
    retry = True
    file_name = None
    while retry:
        try:
            batch_selected = input(f"Enter a number between 1 and {str(len(request_files))} (or 0 to go back): ")
            batch_selected = int(batch_selected)
            if batch_selected == 0:  # exit the submenu
                retry = False
            elif 1 <= batch_selected <= len(request_files):
                file_name = request_files[batch_selected - 1]
                retry = False
        except Exception:
            print(f"Please enter a valid number between 1 and{str(len(request_files) - 1)}")
    if file_name is not None:
        # Launch the selected batch
        llm_prompter.launch_batch(file_name)


def launch_all_batches_choice():
    request_files = os.listdir(os.path.join("batches", "requests"))
    print(f"{len(request_files)} requests batches to execute")
    llm_prompter.launch_all_batches(request_files)
    print("Saving the results in folder:", os.path.join("batches", "results"))
    retrieve_results_choice()


def retrieve_results_choice():
    # if batch_id is None:  # if there is no batch ID set, ask it to the user
    #    batch_id = input("Enter the batch ID (found in the batch_info.txt file):")
    batches_info = llm_prompter.get_batches_info()
    for batch_id, batch_name in batches_info:
        batch_name = batch_name.replace(".jsonl", ".csv")  # change the extension of the results file
        results_file = os.path.join("batches", "results", batch_name)
        if not os.path.exists(results_file):  # only retrieve the results if we do not have them
            file_id = llm_prompter.check_batch_status(batch_id)
            if file_id is not None:  # if the process executed successfully
                # Retrieve the results
                batch_output = llm_prompter.retrieve_batch_results(file_id)
                results = read_batch_putput_file(batch_output)
                results.to_csv(results_file)


def produce_output_file_choice():
    base_path = os.path.join("batches", "results")
    batch_results = os.listdir(base_path)

    for eval_type in evaluations:
        results_df = pd.DataFrame(columns=fieldnames)
        # take the results of the batches and store them in a single dataframe
        for batch_file in batch_results:
            if re.search(eval_type, batch_file) is not None:  # check if the name matches
                partial_df = pd.read_csv(os.path.join(base_path, batch_file), index_col=0)
                results_df = pd.concat([results_df, partial_df],
                                       ignore_index=True)  # add the results of the batch to the tot
        # write results to a file
        output_file = os.path.join("results", eval_type + ".csv")
        with open(output_file, "w", newline="\n") as results:
            results_df.to_csv(results)
            print("Results saved to", output_file)


def compute_metrics_choice():
    results_path = "results"
    results_files = (file for file in os.listdir(results_path)
                     if os.path.isfile(os.path.join(results_path, file)))
    evaluation_types = []
    precisions = []
    recalls = []
    accuracies = []
    f1_scores = []
    log_losses = []
    roc_auc_scores = []
    brier_score_losses = []

    # Function to convert probabilities to float
    def convert_prob(prob):
        if isinstance(prob, str):
            if prob.endswith('%'):
                return float(prob.strip('%')) / 100.0
            else:
                return float(prob) / 100.0 if float(prob) > 1 else float(prob)
        return prob

    for results_file in results_files:
        results_df = pd.read_csv(os.path.join(results_path, results_file), index_col=0)
        evaluation_types.append(results_file.replace(".csv", ""))  # save the evaluation type (e.g., "noURL")
        # Mapping labels to binary values
        results_df['predicted_label'] = results_df['label'].map({'legit': 0, 'phishing': 1})
        # Apply the conversion function to the 'prob' column
        results_df['prob'] = results_df['prob'].apply(convert_prob)
        # Extracting true and predicted labels
        y_true = results_df['true_label']
        y_pred = results_df['predicted_label']
        y_prob = results_df['prob']

        # Calculate metrics
        logloss = log_loss(y_true, y_prob)
        roc_auc = roc_auc_score(y_true, y_prob)
        brier_score = brier_score_loss(y_true, y_prob)
        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        accuracy = accuracy_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)

        log_losses.append(logloss)
        roc_auc_scores.append(roc_auc)
        brier_score_losses.append(brier_score)
        precisions.append(precision)
        recalls.append(recall)
        accuracies.append(accuracy)
        f1_scores.append(f1)

    # Save the DataFrame to a CSV file
    metrics_df = pd.DataFrame({
        'evaluation': evaluation_types,  # this holds the name of the evaluations (noURL, URL_Q=100, etc.)
        'precision': precisions,
        'recall': recalls,
        'accuracy': accuracies,
        'f1_score': f1_scores,
        'log_loss': log_losses,
        'roc_auc': roc_auc_scores,
        'brier_score': brier_score_losses
    })
    metrics_df.to_csv('metrics.csv', index=False)
    print("Metrics saved to", 'metrics.csv')


def load_emails(csv_files):
    emails_df = pd.DataFrame()
    print("Loading emails...")
    for file_name in csv_files:
        df = pd.read_csv(os.path.join('datasets', file_name), sep=",")
        emails_df = pd.concat([emails_df, df])

    # Get only emails in the specified range
    # emails_df = emails_df.iloc[START_INDEX:END_INDEX]
    emails_df["url_info"] = None  # initialize empty column for the URL information

    #  already_processed = load_already_classified_emails(ENRICH_URL)  # get a df with the already processed emails
    for i in range(0, len(emails_df)):
        mail = emails_df.iloc[i]
        mail_urls = [] if len(mail["urls"]) == 0 else mail["urls"].split(" ")  # explode the string into a list
        # If email has no URL OR if email was already processed, skip it
        if len(mail_urls) == 0:  # or (already_processed["mail_id"] == mail["mail_id"]).any():
            emails_df = emails_df.drop(i)
        else:
            # Get additional information about URLs in the email
            if ENRICH_URL:
                # url_to_analyze = mail_urls[0]  # for now, we take the first URL
                url_info = url_enricher.get_dummy_values(QUANTILE, mail["url_location"],
                                                         mail["label"], FALSE_POSITIVES)  # url_enricher.get_url_info(url_to_analyze)
                emails_df.iloc[i, emails_df.columns.get_loc("url_info")] = json.dumps(url_info)
    return emails_df


def load_already_classified_emails(enrich_url):
    if enrich_url:
        file_name = os.path.join('results', 'url_enriched_' + str(QUANTILE) + '.csv')
    else:
        file_name = os.path.join('results', 'no_url_enriched.csv')

    if os.path.exists(file_name):
        y_results = pd.read_csv(file_name, names=fieldnames)
    else:
        y_results = pd.DataFrame(columns=fieldnames)  # empty dataframe
    # else:
    #    open(url_enriched_file, 'a')  # create empty file
    #    y_results_url = pd.DataFrame(columns=fieldnames)
    return y_results


def read_batch_putput_file(batch_result):
    lines = str.split(batch_result, "\n")  # get the individual lines of the jsonl results file in response
    results = []
    for line in lines:
        if len(line) > 0:  # be sure each line is not empty
            try:
                line = json.loads(line)
                if line["response"]["status_code"] == 200:
                    # the request ID was = "{mailID}_{label}"
                    mailID = str.split(line["custom_id"], "_")[0]
                    true_label = str.split(line["custom_id"], "_")[1]
                    try:
                        # get the response content
                        classification_response = line["response"]["body"]["choices"][0]["message"]["content"]
                        classification_response = json.loads(classification_response)
                        y_label = classification_response["label"]
                        y_prob = classification_response["phishing_probability"]
                        result = {"mail_id": mailID, "label": y_label, "prob": y_prob, "true_label": true_label}
                        # print(f"{result['mail_id']},{result['label']},{result['prob']},{result['true_label']}")
                        results.append(result)
                    except Exception as e:
                        # the result is discarded
                        print(e)
                        print(json.dumps(line))
            except Exception as e:
                print(e)
    results_df = pd.DataFrame(results)
    return results_df


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
