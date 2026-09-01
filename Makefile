# hkdf-tree helper targets (building is cargo's job).

.PHONY: man-html
man-html:
	mandoc -T html -O style=man.css man/hkdf-tree.1 > docs/index.html
	cp docs/index.html docs/hkdf-tree.html
