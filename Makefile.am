
AM_MAKEFLAGS = --no-print-directory

lib_LTLIBRARIES =

noinst_LIBRARIES =

noinst_LTLIBRARIES =

bin_PROGRAMS =

sbin_PROGRAMS =

noinst_PROGRAMS =

dist_man_MANS =

dist_noinst_MANS =

CLEANFILES =

EXTRA_DIST =

includedir = @includedir@/bluetooth

include_HEADERS =

AM_CFLAGS = $(WARNING_CFLAGS) $(MISC_CFLAGS)
AM_LDFLAGS = $(MISC_LDFLAGS)

if DATAFILES
dbusdir = $(sysconfdir)/dbus-1/system.d
dbusservicedir = $(datadir)/dbus-1/system-services

dbus_DATA = src/bluetooth.conf
dbusservice_DATA = src/org.bluez.service

confdir = $(sysconfdir)/bluetooth

conf_DATA =

statedir = $(localstatedir)/lib/bluetooth

state_DATA =

if SYSTEMD
systemdunitdir = @SYSTEMD_UNITDIR@

systemdunit_DATA = src/bluetooth.service
endif
endif

plugindir = $(libdir)/bluetooth/plugins

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
else
build_plugindir = $(plugindir)
endif


plugin_LTLIBRARIES =


lib_headers = lib/bluetooth.h lib/hci.h lib/hci_lib.h lib/mgmt.h \
		lib/sco.h lib/l2cap.h lib/sdp.h lib/sdp_lib.h lib/uuid.h \
		lib/rfcomm.h lib/bnep.h lib/cmtp.h lib/hidp.h lib/a2mp.h
local_headers = $(foreach file,$(lib_headers), lib/bluetooth/$(notdir $(file)))

BUILT_SOURCES = $(local_headers) src/builtin.h

include_HEADERS += $(lib_headers)

lib_LTLIBRARIES += lib/libbluetooth.la

lib_libbluetooth_la_SOURCES = $(lib_headers) \
				lib/bluetooth.c lib/hci.c lib/sdp.c lib/uuid.c
lib_libbluetooth_la_LDFLAGS = $(AM_LDFLAGS) -version-info 16:0:13
lib_libbluetooth_la_DEPENDENCIES = $(local_headers)

noinst_LTLIBRARIES += lib/libbluetooth-private.la

lib_libbluetooth_private_la_SOURCES = $(lib_libbluetooth_la_SOURCES)

if SBC
noinst_LTLIBRARIES += sbc/libsbc.la

sbc_libsbc_la_SOURCES = sbc/sbc.h sbc/sbc.c sbc/sbc_math.h sbc/sbc_tables.h \
			sbc/sbc_primitives.h sbc/sbc_primitives.c \
			sbc/sbc_primitives_mmx.h sbc/sbc_primitives_mmx.c \
			sbc/sbc_primitives_iwmmxt.h sbc/sbc_primitives_iwmmxt.c \
			sbc/sbc_primitives_neon.h sbc/sbc_primitives_neon.c \
			sbc/sbc_primitives_armv6.h sbc/sbc_primitives_armv6.c

sbc_libsbc_la_CFLAGS = $(AM_CFLAGS) -finline-functions -fgcse-after-reload \
					-funswitch-loops -funroll-loops

noinst_PROGRAMS += sbc/sbcinfo sbc/sbcdec sbc/sbcenc

sbc_sbcdec_SOURCES = sbc/sbcdec.c sbc/formats.h
sbc_sbcdec_LDADD = sbc/libsbc.la

sbc_sbcenc_SOURCES = sbc/sbcenc.c sbc/formats.h
sbc_sbcenc_LDADD = sbc/libsbc.la

if SNDFILE
noinst_PROGRAMS += sbc/sbctester

sbc_sbctester_LDADD = @SNDFILE_LIBS@ -lm
sbc_sbctest_CFLAGS = $(AM_CFLAGS) @SNDFILE_CFLAGS@
endif
endif

attrib_sources = attrib/att.h attrib/att-database.h attrib/att.c \
		attrib/gatt.h attrib/gatt.c \
		attrib/gattrib.h attrib/gattrib.c attrib/client.h \
		attrib/client.c attrib/gatt-service.h attrib/gatt-service.c

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

btio_sources = btio/btio.h btio/btio.c

builtin_modules =
builtin_sources =
builtin_nodist =
mcap_sources =

if MCAP
mcap_sources += profiles/health/mcap_lib.h profiles/health/mcap_internal.h \
		profiles/health/mcap.h profiles/health/mcap.c \
		profiles/health/mcap_sync.c
endif

if AUDIOPLUGIN
builtin_modules += audio
builtin_sources += audio/main.c \
			audio/manager.h audio/manager.c \
			audio/gateway.h audio/gateway.c \
			audio/headset.h audio/headset.c \
			audio/control.h audio/control.c \
			audio/avctp.h audio/avctp.c \
			audio/avrcp.h audio/avrcp.c \
			audio/device.h audio/device.c \
			audio/source.h audio/source.c \
			audio/sink.h audio/sink.c \
			audio/a2dp.h audio/a2dp.c \
			audio/avdtp.h audio/avdtp.c \
			audio/media.h audio/media.c \
			audio/transport.h audio/transport.c \
			audio/telephony.h audio/a2dp-codecs.h
builtin_nodist += audio/telephony.c

noinst_LIBRARIES += audio/libtelephony.a

audio_libtelephony_a_SOURCES = audio/telephony.h audio/telephony-dummy.c \
				audio/telephony-maemo5.c audio/telephony-ofono.c \
				audio/telephony-maemo6.c
endif

if SAPPLUGIN
builtin_modules += sap
builtin_sources += profiles/sap/main.c profiles/sap/manager.h \
			profiles/sap/manager.c profiles/sap/server.h \
			profiles/sap/server.c profiles/sap/sap.h

builtin_nodist += profiles/sap/sap.c

noinst_LIBRARIES += profiles/sap/libsap.a

profiles_sap_libsap_a_SOURCES = profiles/sap/sap.h profiles/sap/sap-dummy.c \
				profiles/sap/sap-u8500.c
endif

if INPUTPLUGIN
builtin_modules += input
builtin_sources += profiles/input/main.c \
			profiles/input/manager.h profiles/input/manager.c \
			profiles/input/server.h profiles/input/server.c \
			profiles/input/device.h profiles/input/device.c \
			profiles/input/fakehid.c profiles/input/fakehid.h
endif

if HOGPLUGIN
builtin_modules += hog
builtin_sources += profiles/input/hog_manager.c profiles/input/hog_device.h \
			profiles/input/hog_device.c profiles/input/uhid_copy.h
endif

if NETWORKPLUGIN
builtin_modules += network
builtin_sources += profiles/network/main.c \
			profiles/network/manager.h profiles/network/manager.c \
			profiles/network/common.h profiles/network/common.c \
			profiles/network/server.h profiles/network/server.c \
			profiles/network/connection.h \
			profiles/network/connection.c
endif

if SERVICEPLUGIN
builtin_modules += service
builtin_sources += plugins/service.c
endif

if HEALTHPLUGIN
builtin_modules += health
builtin_sources += profiles/health/hdp_main.c profiles/health/hdp_types.h \
		profiles/health/hdp_manager.h profiles/health/hdp_manager.c \
		profiles/health/hdp.h profiles/health/hdp.c \
		profiles/health/hdp_util.h profiles/health/hdp_util.c
endif

if GATTMODULES
builtin_modules += thermometer alert time gatt_example proximity deviceinfo
builtin_sources += profiles/thermometer/main.c \
			profiles/thermometer/manager.h \
			profiles/thermometer/manager.c \
			profiles/thermometer/thermometer.h \
			profiles/thermometer/thermometer.c \
			profiles/alert/main.c profiles/alert/server.h \
			profiles/alert/server.c \
			profiles/time/main.c profiles/time/server.h \
			profiles/time/server.c profiles/time/manager.c \
			profiles/time/manager.h \
			plugins/gatt-example.c \
			profiles/proximity/main.c profiles/proximity/manager.h \
			profiles/proximity/manager.c \
			profiles/proximity/monitor.h \
			profiles/proximity/monitor.c \
			profiles/proximity/reporter.h \
			profiles/proximity/reporter.c \
			profiles/proximity/linkloss.h \
			profiles/proximity/linkloss.c \
			profiles/proximity/immalert.h \
			profiles/proximity/immalert.c \
			profiles/deviceinfo/main.c \
			profiles/deviceinfo/manager.h \
			profiles/deviceinfo/manager.c \
			profiles/deviceinfo/deviceinfo.h \
			profiles/deviceinfo/deviceinfo.c
endif

builtin_modules += formfactor
builtin_sources += plugins/formfactor.c

EXTRA_DIST += plugins/formfactor.c

builtin_modules += storage
builtin_sources += plugins/storage.c

builtin_modules += adaptername
builtin_sources += plugins/adaptername.c

if WIIMOTEPLUGIN
builtin_modules += wiimote
builtin_sources += plugins/wiimote.c
endif

if DBUSOOBPLUGIN
builtin_modules += dbusoob
builtin_sources += plugins/dbusoob.c
endif

if MAINTAINER_MODE
plugin_LTLIBRARIES += plugins/external-dummy.la
plugins_external_dummy_la_SOURCES = plugins/external-dummy.c
plugins_external_dummy_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version \
				    -no-undefined
plugins_external_dummy_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
endif

sbin_PROGRAMS += src/bluetoothd

src_bluetoothd_SOURCES = $(gdbus_sources) $(builtin_sources) \
			$(attrib_sources) $(btio_sources) \
			$(mcap_sources) src/bluetooth.ver \
			src/main.c src/log.h src/log.c \
			src/rfkill.c src/hcid.h src/sdpd.h \
			src/sdpd-server.c src/sdpd-request.c \
			src/sdpd-service.c src/sdpd-database.c \
			src/attrib-server.h src/attrib-server.c \
			src/sdp-xml.h src/sdp-xml.c \
			src/sdp-client.h src/sdp-client.c \
			src/textfile.h src/textfile.c \
			src/glib-helper.h src/glib-helper.c \
			src/oui.h src/oui.c src/uinput.h src/ppoll.h \
			src/plugin.h src/plugin.c \
			src/storage.h src/storage.c \
			src/agent.h src/agent.c \
			src/error.h src/error.c \
			src/manager.h src/manager.c \
			src/adapter.h src/adapter.c \
			src/device.h src/device.c src/attio.h \
			src/dbus-common.c src/dbus-common.h \
			src/event.h src/event.c \
			src/oob.h src/oob.c src/eir.h src/eir.c \
			src/mgmt.c src/mgmt.h
src_bluetoothd_LDADD = lib/libbluetooth-private.la @GLIB_LIBS@ @DBUS_LIBS@ \
								-ldl -lrt
src_bluetoothd_LDFLAGS = $(AM_LDFLAGS) -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/bluetooth.ver

src_bluetoothd_DEPENDENCIES = lib/libbluetooth-private.la

src_bluetoothd_CFLAGS = $(AM_CFLAGS) -DBLUETOOTH_PLUGIN_BUILTIN \
					-DPLUGINDIR=\""$(build_plugindir)"\"
src_bluetoothd_SHORTNAME = bluetoothd

builtin_files = src/builtin.h $(builtin_nodist)

nodist_src_bluetoothd_SOURCES = $(builtin_files)

CLEANFILES += $(builtin_files)

man_MANS = src/bluetoothd.8

if DATAFILES
conf_DATA += src/main.conf
endif

EXTRA_DIST += src/genbuiltin src/bluetooth.conf src/org.bluez.service \
			src/main.conf profiles/network/network.conf \
			profiles/input/input.conf profiles/proximity/proximity.conf \
			audio/audio.conf audio/telephony-dummy.c \
			audio/telephony-maemo5.c audio/telephony-ofono.c \
			audio/telephony-maemo6.c profiles/sap/sap-dummy.c \
			profiles/sap/sap-u8500.c

if AUDIOPLUGIN
if GSTREAMER
gstreamerdir = $(libdir)/gstreamer-0.10

gstreamer_LTLIBRARIES = audio/libgstbluetooth.la

audio_libgstbluetooth_la_SOURCES = audio/gstbluetooth.c audio/gstpragma.h \
				audio/gstsbcenc.h audio/gstsbcenc.c \
				audio/gstsbcdec.h audio/gstsbcdec.c \
				audio/gstsbcparse.h audio/gstsbcparse.c \
				audio/gstavdtpsink.h audio/gstavdtpsink.c \
				audio/gsta2dpsink.h audio/gsta2dpsink.c \
				audio/gstsbcutil.h audio/gstsbcutil.c audio/rtp.h \
				audio/gstrtpsbcpay.h audio/gstrtpsbcpay.c
audio_libgstbluetooth_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version
audio_libgstbluetooth_la_LIBADD = sbc/libsbc.la lib/libbluetooth-private.la \
						@DBUS_LIBS@ @GSTREAMER_LIBS@ \
						-lgstaudio-0.10 -lgstrtp-0.10
audio_libgstbluetooth_la_CFLAGS = -fvisibility=hidden -fno-strict-aliasing \
                               $(AM_CFLAGS) @DBUS_CFLAGS@ @GSTREAMER_CFLAGS@
endif
endif

include Makefile.tools

if DATAFILES
rulesdir = @UDEV_DIR@/rules.d

udev_files =

if HID2HCI
udev_files += scripts/bluetooth-hid2hci.rules
endif

if PCMCIA
udevdir = @UDEV_DIR@

udev_files += scripts/bluetooth-serial.rules

dist_udev_SCRIPTS = scripts/bluetooth_serial
endif

rules_DATA = $(foreach file,$(udev_files), scripts/97-$(notdir $(file)))
endif

CLEANFILES += $(rules_DATA)

EXTRA_DIST += scripts/bluetooth-hid2hci.rules scripts/bluetooth-serial.rules

EXTRA_DIST += doc/manager-api.txt \
		doc/adapter-api.txt doc/device-api.txt \
		doc/service-api.txt doc/agent-api.txt doc/attribute-api.txt \
		doc/network-api.txt doc/input-api.txt doc/audio-api.txt \
		doc/control-api.txt doc/hfp-api.txt doc/health-api.txt \
		doc/sap-api.txt doc/media-api.txt doc/assigned-numbers.txt

AM_YFLAGS = -d

AM_CFLAGS += @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(builddir)/lib -I$(builddir)/src -I$(srcdir)/src \
			-I$(srcdir)/audio -I$(srcdir)/sbc -I$(srcdir)/gdbus \
			-I$(srcdir)/attrib -I$(srcdir)/btio -I$(srcdir)/tools \
			-I$(builddir)/tools -I$(srcdir)/monitor

if MCAP
INCLUDES += -I$(builddir)/health
endif

unit_objects =

if TEST
unit_tests = unit/test-eir

noinst_PROGRAMS += $(unit_tests)

unit_test_eir_SOURCES = unit/test-eir.c src/eir.c src/glib-helper.c
unit_test_eir_LDADD = lib/libbluetooth-private.la @GLIB_LIBS@ @CHECK_LIBS@
unit_test_eir_CFLAGS = $(AM_CFLAGS) @CHECK_CFLAGS@
unit_objects += $(unit_test_eir_OBJECTS)
else
unit_tests =
endif

TESTS = $(unit_tests)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-datafiles

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs ylwrap

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

audio/telephony.c: audio/@TELEPHONY_DRIVER@
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

profiles/sap/sap.c: profiles/sap/@SAP_DRIVER@
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

scripts/%.rules:
	$(AM_V_GEN)cp $(subst 97-,,$@) $@

$(lib_libbluetooth_la_OBJECTS): $(local_headers)

lib/bluetooth/%.h: lib/%.h
	$(AM_V_at)$(MKDIR_P) lib/bluetooth
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

clean-local:
	$(RM) -r lib/bluetooth
