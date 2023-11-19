# streamlit_app.py
import streamlit as st

st.title("ZOPS ☁️ SolutionBooking 🗓️")

def main():

    # Embed the Calendly booking site using an iframe
    calendly_url = "https://calendly.com/zopscloudsoultions/zops-solutions"
    st.markdown(f'<iframe src="{calendly_url}" width="100%" height="800" frameborder="0"></iframe>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
