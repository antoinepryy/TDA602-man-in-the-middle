pandoc -f markdown-implicit_figures --listings -H listings-setup.tex -V geometry:margin=1in -s -o report.pdf README.md
