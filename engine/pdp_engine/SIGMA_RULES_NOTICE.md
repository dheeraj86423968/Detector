# Third-party detection rules: SigmaHQ

`sigma_rules.json` is compiled (pdp_server.tools.sigma_compile) from the SigmaHQ rule repository,
https://github.com/SigmaHQ/sigma, release r2026-07-01 (commit 552f3fee420ef232a8e5790c4fae591847e32347).

The rules are licensed under the Detection Rule License (DRL) 1.1,
https://github.com/SigmaHQ/Detection-Rule-License. As the licence requires, every compiled rule keeps its title,
id, author and references, and alerts raised by a rule name the rule's title. The rules are used unmodified apart
from the format conversion; rules the telemetry cannot evaluate faithfully are left out (see the compiler).
