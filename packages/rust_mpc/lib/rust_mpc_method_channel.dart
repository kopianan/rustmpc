import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'rust_mpc_platform_interface.dart';

/// An implementation of [RustMpcPlatform] that uses method channels.
class MethodChannelRustMpc extends RustMpcPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('rust_mpc');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
