import streamlit as st  
from streamlit_lottie import st_lottie

# Using markdown to center the title
st.markdown("<h1 style='text-align: center;'>ZOPS Secure ☁️ Storage Solution</h1>", unsafe_allow_html=True)
# If the lottie library supports it, you might be able to adjust its size, but you'll need to check its documentation for more information.
st_lottie("https://lottie.host/31137d38-0b0f-4005-931e-d3f811051972/W1GhQ7KlYg.json")

# How to use section
st.write("## How to Use ZOPS Secure ☁️ Storage App")

# ZopsCloud Management
st.write("1. **ZOPS Cloud Management**:")
with st.expander("Details"):  # Creates an expandable section
    st.write("- **Creation**: Follow the steps to create your ZopsCloud account.")
    st.write("- **Subscribe**: Only subscribed users will be available to use ZOPS Secure Cloud Storage App.")
    st.write("- **Subscribe**: Subscribed to use ZOPS Secure Cloud Storage App by clciking on registration tab and click Login wuth Google, procced to payment of $100 Monthly Subscrption.")
    st.write("- **Subscriber**: Once you are a Subscribed user you will then be able to register to use ZOPS Secure ☁️ Storage App")
    st.write("- **Register**: Input details carefully to ensure a smooth registration process.")
    st.write("- **Login**: Use your credentials to access your Storage Unit.")

# Container Management
st.write("2. **ZOPS CloudContainer Management**:")
with st.expander("Details"):
    st.write("- **Creation**: Enter a name in the text box to create a new storage container. Click the 'Create New Storage' button after input.")
    st.write("- **Selection**: Choose your newly created Zops Cloud Storage from the dropdown list.")
    st.write("- **File Upload**: You must create a Storage account first , Once you've selected or created a container, you can use the file uploader to add files to your ZOPS Storage.")
    st.write("- **File preview**: You must upload files to the storage accounts you create first before you can view or preview any files in a storage account.")

# File Management
st.write("3. **ZOPS CloudFile View & Preview Files**:")
with st.expander("Details"):
    st.write("- **View & Preview Files **: Use the 'Preview' button to view contents of your files.")

# Contact form reference
st.write("""
For any other questions, please refer to the official Contact form in the app and provide your username and email that was used when signed up!
""")
