def judge(input_text):
    if "ignore" in input_text.lower() or "send email" in input_text.lower():
        return "MALICIOUS"
    return "CLEAN" 
