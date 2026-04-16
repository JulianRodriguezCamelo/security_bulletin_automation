import openpyxl

file_path = r"C:\Users\Usuario\Documents\Casos_inteligencia_de_amenazas\Informe_Amenazas.xlsx"

try:
    wb = openpyxl.load_workbook(file_path)
    ws = wb["Registro de Amenazas"]
    print(f"Sheet: {ws.title}")
    for row in ws.iter_rows(min_row=1, max_row=5, values_only=True):
        print(row[:5]) # Show first 5 columns
except Exception as e:
    print(f"Error: {e}")
