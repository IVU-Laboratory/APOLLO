import openai
import json
import os
import asyncio
from g4f.client import Client
from g4f.Provider import RetryProvider, Bing, Phind, FreeChatgpt, Liaobots, You, Llama

SEED = 42
MODEL = "gpt-4"  # "gpt-3.5-turbo-1106"
TEMPERATURE = 0.0001

# Set a global client for GPT4free
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
client = Client(
    provider=RetryProvider([Bing, Phind, FreeChatgpt, Liaobots, You, Llama], shuffle=False)
)


def classify_email(email_input, feature_to_explain=None, url_info=None, explanations_min=3, explanations_max=6, model=MODEL):
    # Initial Prompt
    messages = [
        {"role": "system", "content": f'''You are a cybersecurity and human-computer interaction expert that has the goal to detect
        if an email is legitimate or phishing and help the user understand why a specific email is dangerous (or genuine), in order
        to make more informed decisions.
        The user will submit the email (headers + subject + body) optionally accompanied by information of the URLs in the email as:
        - server location;
        - VirusTotal scans reporting the number of scanners that detected the URL as harmless, undetected, suspicious, malicious;
        - number of blacklists in which the linked domain was found.

        Your goal is to output a JSON object containing:
        - The classification result (label).
        - The probability in percentage of the email being phishing (0%=email is surely legitimate, 100%=email is surely phishing) (phishing_probability).
        - A list of persuasion principles that were applied by the alliged attacker (if any); each persuasion principle should be an object containing:
            the persuasion principle name (authority, scarcity, etc.),
            the part of the email that makes you say that persuasion principle is being applied;
            a brief rationale for each principle.
        - A list of {explanations_min} to {explanations_max} features that could indicate the danger (or legitimacy) of the email; the explanations must be understandable by users with no cybersecurity or computers expertise.


        Desired format:
        label: <phishing/legit>
        phishing_probability: <0-100%>
        persuasion_principles: [array of persuation principles, each having: {{name, specific sentences, rationale}} ]
        explanation: [array of {explanations_min}-{explanations_max} features explained]'''
         }
    ]
    # User input (email)
    headers = str(email_input["headers"])
    subject = email_input["subject"]
    body = email_input["body"]
    email_prompt = f'''Email:
          """
          [HEADERS]
            {headers}
          [\HEADERS]
          [SUBJECT] {subject} [\SUBJECT]
          [BODY]
          {body}
          [\BODY]
          """
          '''
    # Add the url_info if it exists
    if url_info is not None:
        email_prompt += f"""

          ######

          URL Information:
          {str(url_info)}"""

    messages.append({"role": "user", "content": email_prompt})
    # Get the classification response

    client = Client()
    response = client.chat.completions.create(
        model=model,
        seed=SEED,
        temperature=TEMPERATURE,
        messages=messages,
        response_format={"type": "json_object"}
    )
    classification_response = response.choices[0].message.content

    messages.append({"role": "assistant",
                     "content": f"{classification_response}"})  # attach the response string for the second prompt

    # Try getting the JSON object from the response
    try:
        classification_response = json.loads(classification_response)
    except:
        print("Invalid JSON format in the response")
        return classification_response, ""

    if "label" in classification_response:
        predicted_label = classification_response['label']
        if predicted_label == "legit":
            # If the classification == legit, then exit the function
            return classification_response, "The email is genuine"
        else:
            # Otherwise, we ask GPT to produce the warning message
            if feature_to_explain is None:
                # Automatically take the most relevant feature
                messages.append(
                    {"role": "user", "content": """
              Now take the most relevant feature among the ones in your explanations and construct a brief explanation message (max 50 words) directed to naive users (with no knowledge of cybersecurity) that will follow this structure:`
              1. description of the most relevant phishing feature
              2. explanation of the hazard
              3. consequences of a successful phishing attack
              For example, a message that explains that a URL in the email (PHISHING_URL) is imitating another legitimate one (SAFE_URL), would be:
              "The target URL [PHISHING_URL] is an imitation of the original one, [SAFE_URL]. This site might be intended to take you to a different place. You might be disclosing private information.”.
              Another example of explanation about the domain of a website being suspiciously young would be:
              "This website is very young (created [N] days ago). Fraudulent websites have a similar age. There is a potential risk of being cheated if you proceed."
              Another example of explaining that the email is suspicious because a domain linked in the email is hosted in a country with bad reputation would be:
              "The host of the target website is in [COUNTRY], which is where most attacks originate. Sharing your private information here is risky."

              Desired format:
              [description of the feature]. [hazard explanation]. [consequences of a successful attack].
              """}
                )
            else:
                # Be primed about the feature to explain
                messages.append(
                    {"role": "user", "content": f"""
              Consider that the previous email is suspicious because {feature_to_explain["description"]}: construct a brief explanation message (max 50 words) directed to naive users (with no knowledge of cybersecurity) that will follow this structure:`
              1. description of the feature (in this case {feature_to_explain["name"]})
              2. explanation of the hazard
              3. consequences of a successful phishing attack
              For example, a message that explains that a URL in the email (PHISHING_URL) is imitating another legitimate one (SAFE_URL), would be:
              "The target URL [PHISHING_URL] is an imitation of the original one, [SAFE_URL]. This site might be intended to take you to a different place. You might be disclosing private information.”.
              Another example of explanation about the domain of a website being suspiciously young would be:
              "This website is very young (created [N] days ago). Fraudulent websites have a similar age. There is a potential risk of being cheated if you proceed."
              Another example of explaining that the email is suspicious because a domain linked in the email is hosted in a country with bad reputation would be:
              "The host of the target website is in [COUNTRY], which is where most attacks originate. Sharing your private information here is risky."

              Desired format:
              [description of the feature]. [hazard explanation]. [consequences of a successful attack].
              """}
                )
            response_2 = client.chat.completions.create(
                model=model,
                seed=SEED,
                temperature=TEMPERATURE,
                messages=messages
            )
            classification_response = response.choices[0].message.content
            explanation_response = response_2.choices[0].message.content
        return classification_response, explanation_response
    else:  # Error: response in wrong format
        print("The response does not contain the predicted label (phishing/non-phishing)")
        return classification_response, ""


def set_api_key():
    openai.api_key = os.getenv('OPENAI_API')


def classify_email_minimal(email_input, url_info=None, model=MODEL):
    messages = [
        {"role": "system", "content": f'''You are a cybersecurity and human-computer interaction expert that has the goal to detect
           if an email is legitimate or phishing and help the user understand why a specific email is dangerous (or genuine), in order
           to make more informed decisions.
           The user will submit the email (headers + subject + body) optionally accompanied by information of the URLs in the email as:
           - server location;
           - VirusTotal scans reporting the number of scanners that detected the URL as harmless, undetected, suspicious, malicious;
           - number of blacklists in which the linked domain was found.

           Your goal is to output a JSON object containing:
           - The classification result (label).
           - The probability in percentage of the email being phishing (0%=email is surely legitimate, 100%=email is surely phishing) (phishing_probability).

           Desired format:
           label: <phishing/legit>
           phishing_probability: <0-100%>'''
         }
    ]
    # User input (email)
    headers = str(email_input["headers"])
    subject = email_input["subject"]
    body = email_input["body"]
    email_prompt = f'''Email:
             """
             [HEADERS]
               {headers}
             [\HEADERS]
             [SUBJECT] {subject} [\SUBJECT]
             [BODY]
             {body}
             [\BODY]
             """
             '''
    # Add the url_info if it exists
    if url_info is not None:
        email_prompt += f"""

             ######

             URL Information:
             {str(url_info)}"""

    messages.append({"role": "user", "content": email_prompt})
    try:
        # Get the classification response
        response = client.chat.completions.create(
            model=model,
            seed=SEED,
            temperature=TEMPERATURE,
            messages=messages,
            response_format={"type": "json_object"}
        )
        classification_response = response.choices[0].message.content
        # Try getting the JSON object from the response
    except:
        print("Error in making the request to the LLM")
        return "", None
    try:
        classification_response = json.loads(classification_response)
    except:
        print("Invalid JSON format in the response")
        return classification_response, None

    if "label" in classification_response and "phishing_probability" in classification_response:
        predicted_label = classification_response['label']
        probability = classification_response['phishing_probability']
        return predicted_label, probability
    else:
        print("The response does not contain the predicted label (phishing/non-phishing)")
        return classification_response, ""
