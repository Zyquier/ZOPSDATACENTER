import streamlit as st

# Title and Header using Streamlit
st.title(":mailbox: ZOPS Secure ☁️ Storage User Form:")
st.header("Get In Touch With Me, for any issue you are having!")

# HTML Form
contact_form = """
<div style="margin: 0 auto; width: 50%; text-align: center;">
    <form action="https://formsubmit.co/zopstech@gmail.com" method="POST">
        <input type="hidden" name="_captcha" value="false">
        <input type="text" name="username" placeholder="Your username" required style="width: 100%; margin-bottom: 10px; padding: 10px;">
        <input type="email" name="email" placeholder="Your email" required style="width: 100%; margin-bottom: 10px; padding: 10px;">
        <textarea name="message" placeholder="Describe your issue here" style="width: 100%; height: 100px; margin-bottom: 10px; padding: 10px;"></textarea>
        <button type="submit" style="padding: 10px 20px; width: 100%;">Send</button>
    </form>
</div>
"""

# Render HTML Form
st.markdown(contact_form, unsafe_allow_html=True)
