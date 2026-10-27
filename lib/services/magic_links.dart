import 'package:app_links/app_links.dart';

/// The platform plugin forwards both launch URLs and links to an open window.
Stream<Uri> nativeMagicLinks() => AppLinks().uriLinkStream;
