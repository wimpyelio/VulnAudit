import streamlit.web.cli as stcli
import sys

if __name__ == "__main__":
    sys.argv = ["streamlit", "run", "scanner/dashboard.py"] + sys.argv[1:]
    raise SystemExit(stcli.main())
