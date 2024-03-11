import preprocessor
import url_enricher
import llm_prompter
import os
from dotenv import load_dotenv

GPT_MODEL = "gpt-4-1106-preview"  # "gpt-3.5-turbo-0613"
ENRICH_URL = False


def main():
    load_dotenv()
    llm_prompter.set_api_key()  # Statically set the API key for OpenAI

    # Open and preprocess an email
    email_filename = "email_name.eml"  # ENTER THE EMAIL FILE NAME HERE
    email_filename = os.path.join("input_files", email_filename)
    with open(email_filename, "rb") as email_byes:
        mail = email_byes.read()
        mail = preprocessor.preprocess_email(mail)
        # Print or use the extracted subject, header, and body as needed
        """print("Subject:", mail["subject"])
        print("Headers:")
        print(mail["headers"])
        print("Body:")
        print(mail["body"])
        print("URLS:")
        print(mail["urls"])"""
        # Gather additional information about URLs in the email
    if len(mail["urls"]) > 0 and ENRICH_URL:
        # Call remote API to gather online URL information
        url_to_analyze = mail["urls"][0]  # for now, we take the first URL
        url_info = url_enricher.get_url_info(url_to_analyze)
    else:
        url_info = None

    # Call GPT-3.5-turbo for email phishing classification (automatic feature detection)
    classification_response_3dot5, warning_msg_3dot5 = llm_prompter.classify_email(mail, url_info,
                                                                                   model="gpt-3.5-turbo-1106")
    print(classification_response_3dot5)
    print(warning_msg_3dot5)


if __name__ == "__main__":
    main()
