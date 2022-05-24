/// bindings for `gg18`

import 'package:ffi/ffi.dart' as ffi;
import 'dart:ffi';
import 'dart:io';

// ignore_for_file: unused_import, camel_case_types, non_constant_identifier_names
final DynamicLibrary _dl = _open();
DynamicLibrary _open() {
  if (Platform.isAndroid) return DynamicLibrary.open('libgg18_ffi.so');
  if (Platform.isIOS) return DynamicLibrary.executable();
  throw UnsupportedError('This platform is not supported.');
}

/// C function `error_message_utf8`.
int error_message_utf8(
  Pointer<ffi.Utf8> buf,
  int length,
) {
  return _error_message_utf8(buf, length);
}
final _error_message_utf8_Dart _error_message_utf8 = _dl.lookupFunction<_error_message_utf8_C, _error_message_utf8_Dart>('error_message_utf8');
typedef _error_message_utf8_C = Int32 Function(
  Pointer<ffi.Utf8> buf,
  Int32 length,
);
typedef _error_message_utf8_Dart = int Function(
  Pointer<ffi.Utf8> buf,
  int length,
);

/// C function `getSignalServerCert`.
void getSignalServerCert(
  int port,
) {
  _getSignalServerCert(port);
}
final _getSignalServerCert_Dart _getSignalServerCert = _dl.lookupFunction<_getSignalServerCert_C, _getSignalServerCert_Dart>('getSignalServerCert');
typedef _getSignalServerCert_C = Void Function(
  Int64 port,
);
typedef _getSignalServerCert_Dart = void Function(
  int port,
);

/// C function `last_error_length`.
int last_error_length() {
  return _last_error_length();
}
final _last_error_length_Dart _last_error_length = _dl.lookupFunction<_last_error_length_C, _last_error_length_Dart>('last_error_length');
typedef _last_error_length_C = Int32 Function();
typedef _last_error_length_Dart = int Function();

/// C function `store_dart_post_cobject`.
void store_dart_post_cobject(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
) {
  _store_dart_post_cobject(ptr);
}
final _store_dart_post_cobject_Dart _store_dart_post_cobject = _dl.lookupFunction<_store_dart_post_cobject_C, _store_dart_post_cobject_Dart>('store_dart_post_cobject');
typedef _store_dart_post_cobject_C = Void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
typedef _store_dart_post_cobject_Dart = void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
