# Use an official Python runtime as a parent image
FROM python:3.11.1

# Set the working directory to /app in the container
WORKDIR /app

# Copy the Zops and pages directories into the container
COPY .streamlit ./.streamlit
COPY Zops ./Zops
COPY pages ./pages


COPY ZOPS_Secure_Cloud_Storage_Solutions.py .

# Copy the requirements.txt file from the Zops directory into the current workdir
COPY requirements.txt .

# Install the Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Streamlit runs on port 8501 by default, expose it
EXPOSE 8501

# Command to run the Streamlit app
CMD ["streamlit", "run", "ZOPS_Secure_Cloud_Storage_Solutions.py"]

# Use this setting to run Streamlit in headless mode
ENV STREAMLIT_SERVER_HEADLESS=true
