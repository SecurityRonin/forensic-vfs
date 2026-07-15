# Build the universal-reader paper. Requires XeLaTeX + BibTeX (TeX Live / MacTeX).
PAPER = universal-reader

$(PAPER).pdf: $(PAPER).tex $(PAPER).bib
	xelatex $(PAPER)
	bibtex $(PAPER)
	xelatex $(PAPER)
	xelatex $(PAPER)

.PHONY: clean
clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out
