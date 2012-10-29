#
# Copyright (c) 2011, 2012 The University of Utah
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

ifdef TRANG
  TRANGCMD = java -jar ${TRANG}
else
  TRANGCMD = trang
endif

SCHEMAS = debuginfo.xsd target.xsd analysis.xsd

all: $(SCHEMAS)

clean:
	rm $(SCHEMAS) *common.xsd

%.xsd: %.rnc common.rnc
	mkdir -p tmp
	$(TRANGCMD) $< tmp/$@
	mv tmp/common.xsd $(@:.xsd=)-common.xsd
	sed "s/common.xsd/$(@:.xsd=)-common.xsd/" tmp/$@ > $@
	rm tmp/$@
	#mv tmp/$@ $@
	rmdir tmp

.PHONY: clean
