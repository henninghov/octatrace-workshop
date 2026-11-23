import 'dart:io';

/// GUI-launched macOS apps may not inherit Homebrew's executable paths.
Map<String, String> workshopToolEnvironment() => {
  'PATH': [
    Platform.environment['PATH'] ?? '',
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
  ].where((part) => part.isNotEmpty).join(':'),
};
