import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:octatrace_workshop/domain/factory_enrollment.dart';
import 'package:octatrace_workshop/domain/registry.dart';
import 'package:octatrace_workshop/domain/workshop_controller.dart';
import 'package:octatrace_workshop/ui/workshop_app.dart';

import 'factory_fixtures.dart' as f;
import 'widget_test.dart' as base;
import 'ui_flow_test.dart' show MemoryEvidence;
import 'provisioning_test.dart' as p;

class FactoryUiGateway extends p.SetupGateway implements FactoryGateway {
  final backend = f.FactoryFake();
  bool hasProof = true;
  String? owner;
  String deviceState = 'provisioned';
  @override
  Future<void> exchangeLink(String code) async {
    account = f.account;
  }

  @override
  Future<Registry> load() async => Registry.fromJson({
    'articles': [
      {
        'id': f.revision,
        'article_id': f.enrollment,
        'code': '${backend.role.toUpperCase()}-SYNTHETIC',
        'name': 'Synthetic fixture',
        'role': backend.role,
        'revision': 1,
        'case_version': 'A',
        'parts': <Json>[],
      },
    ],
    'devices': [
      {
        'id': f.unit(role: backend.role).id,
        'serial': 'D000000000001',
        'article_revision_id': f.revision,
        'provisioning_state': deviceState,
        'owner_user_id': owner,
      },
    ],
    'runs': [
      if (hasProof)
        {
          'id': f.proof,
          'device_id': f.unit(role: backend.role).id,
          'operator_user_id': f.account,
          'event_type': 'provisioned',
        },
    ],
  });
  @override
  Future<Json> factoryStatus(String id) => backend.factoryStatus(id);
  @override
  Future<Json> issueFactory({
    required String requestId,
    required String provisioningRequestId,
    required String deviceId,
    required String role,
  }) => backend.issueFactory(
    requestId: requestId,
    provisioningRequestId: provisioningRequestId,
    deviceId: deviceId,
    role: role,
  );
  @override
  Future<String> revealFactory({
    required String requestId,
    required String deviceId,
  }) => backend.revealFactory(requestId: requestId, deviceId: deviceId);
}

void main() {
  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final font = FontLoader('Excon')
      ..addFont(rootBundle.load('assets/fonts/Excon-Regular.otf'))
      ..addFont(rootBundle.load('assets/fonts/Excon-Medium.otf'));
    await font.load();
    await const SvgAssetLoader('assets/branding/wordmark.svg').loadBytes(null);
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  late FactoryUiGateway gateway;
  late WorkshopController c;
  setUp(() {
    gateway = FactoryUiGateway();
    c = WorkshopController(
      gateway,
      base.Runner(),
      MemoryEvidence(),
      provisioner: p.SetupRunner(),
    );
  });
  tearDown(() => c.dispose());
  Future<void> show(
    WidgetTester t, {
    Size size = const Size(1300, 1100),
    double scale = 1,
  }) async {
    await t.binding.setSurfaceSize(size);
    addTearDown(() => t.binding.setSurfaceSize(null));
    await base.signIn(c);
    await t.pumpWidget(
      Directionality(
        textDirection: TextDirection.ltr,
        child: Banner(
          message: 'SYNTHETIC TEST',
          location: BannerLocation.topEnd,
          child: MediaQuery(
            data: MediaQueryData(textScaler: TextScaler.linear(scale)),
            child: WorkshopApp(controller: c),
          ),
        ),
      ),
    );
    await t.pumpAndSettle();
    await t.tap(find.byTooltip('Open device'));
    await t.pumpAndSettle();
  }

  Future<void> tap(WidgetTester t, String text) async {
    await t.ensureVisible(find.text(text));
    await t.tap(find.text(text));
    await t.pumpAndSettle();
  }

  testWidgets(
    'explicit issue, Ready refresh, private reveal/raw copy and Hide use the real panel',
    (t) async {
      await show(t);
      expect(find.text('Factory credential not issued'), findsOneWidget);
      expect(find.byType(QrImageView), findsNothing);
      await tap(t, 'Issue factory credential and claim code');
      expect(gateway.backend.issues, 1);
      expect(
        find.text('Factory credential issued · claim QR ready'),
        findsOneWidget,
      );
      expect(find.byType(QrImageView), findsNothing);
      await tap(t, 'Reveal private claim QR');
      expect(gateway.backend.reveals, 1);
      expect(find.byType(QrImageView), findsOneWidget);
      await tap(t, 'Raw claim payload');
      expect(find.text(f.qrRow()['text'] as String), findsOneWidget);
      await tap(t, 'Hide QR');
      expect(find.byType(QrImageView), findsNothing);
      expect(find.text(f.qrRow()['text'] as String), findsNothing);
      await tap(t, 'Refresh claim-code status');
      expect(gateway.backend.statuses, greaterThan(1));
    },
  );
  testWidgets(
    'no proof blocks issuance; unavailable status, pending and sign-in recovery are clear',
    (t) async {
      gateway.hasProof = false;
      await show(t);
      expect(
        t
            .widget<FilledButton>(
              find.widgetWithText(
                FilledButton,
                'Issue factory credential and claim code',
              ),
            )
            .onPressed,
        isNull,
      );
      expect(find.textContaining('confirmed USB proof'), findsOneWidget);
      gateway.backend.failure = const FactoryFailure();
      await tap(t, 'Refresh claim-code status');
      expect(
        find.textContaining('Could not complete this request'),
        findsOneWidget,
      );
      gateway.backend.failure = null;
      gateway.backend.state = 'pending';
      await tap(t, 'Refresh claim-code status');
      expect(find.text('Factory enrollment pending'), findsOneWidget);
      await tap(t, 'Sign in again');
      expect(c.access, Access.signedOut);
      expect(find.text('Send sign-in link'), findsOneWidget);
      expect(gateway.backend.reveals, 0);
    },
  );
  testWidgets(
    'cancel/late response, account change, lifecycle and navigation hide private state',
    (t) async {
      gateway.backend.state = 'ready';
      await show(t);
      gateway.backend.holdReveal = Completer();
      await t.ensureVisible(find.text('Reveal private claim QR'));
      await t.tap(find.text('Reveal private claim QR'));
      await t.pump();
      await t.ensureVisible(find.text('Cancel'));
      await t.tap(find.text('Cancel'));
      await t.pump();
      gateway.backend.holdReveal!.complete(f.qrRow()['text'] as String);
      await t.pumpAndSettle();
      expect(find.byType(QrImageView), findsNothing);
      gateway.backend.holdReveal = null;
      await tap(t, 'Reveal private claim QR');
      expect(find.byType(QrImageView), findsOneWidget);
      t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await t.pump();
      expect(find.byType(QrImageView), findsNothing);
      t.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tap(t, 'Reveal private claim QR');
      await t.tap(find.text('Articles'));
      await t.pumpAndSettle();
      expect(find.byType(QrImageView), findsNothing);
      await t.tap(find.text('Provisioning'));
      await t.pumpAndSettle();
      expect(find.byType(QrImageView), findsNothing);
      await tap(t, 'Reveal private claim QR');
      await c.signOut();
      await t.pumpAndSettle();
      expect(find.byType(QrImageView), findsNothing);
    },
  );
  testWidgets(
    'claimed CORE remains revealable, retired device is not issuable; narrow layout fits',
    (t) async {
      gateway.backend.role = 'Core';
      gateway.backend.state = 'ready';
      gateway.owner = f.account;
      await show(t, size: const Size(850, 1100), scale: 1.6);
      expect(
        find.text('Issue factory credential and claim code'),
        findsNothing,
      );
      await tap(t, 'Reveal private claim QR');
      expect(find.byType(QrImageView), findsOneWidget);
      expect(t.takeException(), isNull);
      gateway.deviceState = 'retired';
      await c.refresh();
      await t.pumpAndSettle();
      expect(find.byType(QrImageView), findsNothing);
      expect(
        find.textContaining('Factory issuance is available'),
        findsOneWidget,
      );
      expect(find.text('Reveal private claim QR'), findsNothing);
    },
  );
  for (final dark in [false, true]) {
    testWidgets('synthetic factory QR ${dark ? 'dark' : 'light'} visual', (
      t,
    ) async {
      gateway.backend.state = 'ready';
      gateway.backend.role = dark ? 'Core' : 'Link';
      await show(t, size: const Size(1300, 1500));
      if (dark) await tap(t, 'Dark mode');
      await tap(t, 'Reveal private claim QR');
      await t.ensureVisible(find.text('Raw claim payload'));
      await t.pumpAndSettle();
      await expectLater(
        find.byType(WorkshopApp),
        matchesGoldenFile('goldens/factory-qr-${dark ? 'dark' : 'light'}.png'),
      );
    }, tags: 'golden');
  }
}
