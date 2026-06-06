# report_exporter.py

import pandas as pd

def export_csv(findings):

    df = pd.DataFrame(findings)

    output_file = "output/report.csv"

    df.to_csv(output_file, index=False)

    return output_file