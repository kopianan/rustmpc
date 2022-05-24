import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'rust_mpc_method_channel.dart';

abstract class RustMpcPlatform extends PlatformInterface {
  /// Constructs a RustMpcPlatform.
  RustMpcPlatform() : super(token: _token);

  static final Object _token = Object();

  static RustMpcPlatform _instance = MethodChannelRustMpc();

  /// The default instance of [RustMpcPlatform] to use.
  ///
  /// Defaults to [MethodChannelRustMpc].
  static RustMpcPlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [RustMpcPlatform] when
  /// they register themselves.
  static set instance(RustMpcPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
