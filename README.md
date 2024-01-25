AntiPhish-LLM is a tool written in Python 3.10.12 and powered by GPT-4-turbo ([gpt-4-1106-preview]([url](https://help.openai.com/en/articles/8555510-gpt-4-turbo))) to:
- **classify** an email as **phishing** or legitimate, and
- **generate an explanation** for the user in the case of a phishing email.

AntiPhish-LLM takes in input an email in _.eml format_ and, thanks to the preprocessor module, removes any HTML tag and saves information about the links in the email (as done in [1]). To overcome the knowledge cut-off of GPT-4, we enriched the link with online information. Specifically, we query the VirusTotal and BlackListChecker APIs to see if the link is malicious, and BigDataCloud to see the server location, useful for the explanation phase. Finally, the email link and this additional information are used to fill in two templates of GPT-4 prompts, which allow AntiPhish-LLM to classify the email and generate the explanation. 

The core of the tool is the set of the GPT-4 prompts, thus we devoted particular care to manually designing and iteratively refining them according to the best practices of prompt-engineering [2-4]. Notably, we followed a few-shot prompting approach, as also suggested by OpenAI [4]. The generated explanations follow the structure defined in [5]: “Feature description + Hazard Explanation + Consequences of not complying with the warning”. This structure is grounded on warning theory for the design of warning messages [6]. Moreover, the generated explanations revolve around a set of email features that are valuable for users in making decisions regarding phishing content [5,7] i.e., are:

- (1) Top-Level Domain in the URL is Mispositioned (e.g., as in the URL “www.amazon.com.cz”); 
- (2) the URL is an IP address; 
- (3) Mismatch between the displayed and actual link; 
- (4) the URL points to a very young domain.

This tool was used in the study "Can LLMs help protect users from phishing attacks? An exploratory study", submitted for the CHI'24 conference, Late-Breaking Work track.

### Supplementary material

In the file emails+warnings.zip are stored the emails (in .html format) to which users in the study "Can LLMs help protect users from phishing attacks? An exploratory study" were exposed, together with the warnings shown (in .png format). Emails are named EX.html, and warnings are named WX.png, where X is the experimental condition (from 1 to 4).

"Stat test details.xls" contains statistical data about the results of the study. 

### References

[1] Misra, K. and Rayz, J. T.. 2022. LMs go Phishing: Adapting Pre-trained Language Models to Detect Phishing Email.

[2] Liu, P., Yuan, Q., Fu, J., Jiang, Z., Hayashi, H. and Neubig, G. 2023. Pre-train, Prompt, and Predict: A Systematic Survey of Prompting Methods in Natural Language Processing.ACM Comput. Surv., 55, 9, Article 195. https://doi.org/10.1145/3560815

[3] DAIR.AI Prompt Engineering Guide. https://www.promptingguide.ai

[4] Shieh, J. Best practices for prompt engineering with OpenAI API. OpenAI https://help.openai.com/en/articles/6654000-best-practices-for-prompt-engineering-with-openai-api

[5] Desolda, G., Aneke, J., Ardito, C., Lanzilotti, R. and Costabile, M. F. 2023. Explanations in warning dialogs to help users defend against phishing attacks.Explanations in warning dialogs to help users defend against phishing attacks, 176 2023/08/01, 103056. https://www.sciencedirect.com/science/article/pii/S1071581923000654

[6] Bauer, L., Bravo-Lillo, C., Cranor, L. and Fragkaki, E. 2013. Warning Design Guidelines (CMU-CyLab-13-002).

[7] Buono, P., Desolda, G., Greco, F. and Piccinno, A.2023. Let warnings interrupt the interaction and explain: designing and evaluating phishing email warnings. In Proceedings of the CHI Conference on Human Factors in Computing Systems (Short Let warnings interrupt the interaction and explain: designing and evaluating phishing email warnings), April 2023, 2023, Hamburg Germany. ACM, 1-6. 
