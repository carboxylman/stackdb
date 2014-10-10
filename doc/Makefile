#
# Copyright (c) 2014 The University of Utah
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#

ifndef PANDOC
    PANDOC = pandoc
endif
ifndef DOXYGEN
    DOXYGEN = doxygen
endif

all: doc-www doc-pdf doc-all doc-api

doc-all:
	$(PANDOC) -s -S --toc --toc-depth=4 -N --chapters \
		-o stackdb-alldocs.pdf \
		../README ../INSTALL user-guide.md hacker-guide.md
	$(PANDOC) -s -S --toc --toc-depth=4 -N --self-contained -c style.css \
		-o all.html \
		../README ../INSTALL user-guide.md hacker-guide.md

doc-pdf:
	$(PANDOC) -s -S --toc --toc-depth=4 -N \
		-o stackdb-user-guide.pdf user-guide.md
	$(PANDOC) -s -S --toc --toc-depth=4 -N \
		-o stackdb-hacker-guide.pdf hacker-guide.md

doc-www:
	$(PANDOC) -S -c style.css \
		-o index.html index.md
	$(PANDOC) -S --toc --toc-depth=4 -c style.css \
		-o about.html ../README
	$(PANDOC) -S --toc --toc-depth=4 -c style.css \
		-o install.html ../INSTALL
	$(PANDOC) -S --toc --toc-depth=4 -c style.css \
		-o user-guide.html user-guide.md
	$(PANDOC) -S --toc --toc-depth=4 -c style.css \
		-o hacker-guide.html hacker-guide.md

doc-api:
	$(DOXYGEN) doxygen-config

clean:
	rm -f *.pdf index.html all.html about.html install.html user-guide.html hacker-guide.html
	rm -rf api/*

.PHONY: clean
