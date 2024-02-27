import streamlit as st
import pandas as pd
import numpy as np

st.header("Welcome to XOR Cipher!")
st.write("What is your name?")

txt_FNAME = st.text_area("FIRS NAME:")
txt_LNAME = st.text_area("LAST NAME:")

btn_submit = st.button("submit")

if btn_submit:
    st.error(f"Hello {txt_FNAME} {txt_LNAM}!")
        
  