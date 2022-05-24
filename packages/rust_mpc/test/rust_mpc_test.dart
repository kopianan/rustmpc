import 'package:flutter_test/flutter_test.dart';
import 'package:rust_mpc/rust_mpc.dart';
import 'package:rust_mpc/rust_mpc_platform_interface.dart';
import 'package:rust_mpc/rust_mpc_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockRustMpcPlatform 
    with MockPlatformInterfaceMixin
    implements RustMpcPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final RustMpcPlatform initialPlatform = RustMpcPlatform.instance;

  test('$MethodChannelRustMpc is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelRustMpc>());
  });

  test('getPlatformVersion', () async {
    RustMpc rustMpcPlugin = RustMpc();
    MockRustMpcPlatform fakePlatform = MockRustMpcPlatform();
    RustMpcPlatform.instance = fakePlatform;
  
    expect(await rustMpcPlugin.getPlatformVersion(), '42');
  });
}
