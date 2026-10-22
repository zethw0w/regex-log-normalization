# Regex & Normalização de Logs

Resolução dos **exercícios de Regex** (Defense Operations / FIAP): extração de campos e normalização de logs estilo SIEM, do nível básico à detecção SOC. Validado com `grep -P`, `sed -E` e `awk` no WSL.

## Níveis

- **Nível 1 (básico):** extração de IP `\d{1,3}(\.\d{1,3}){3}`, usuário `for \K\w+`, porta `port \K\d+`.
- **Nível 2 (campos):** parse de log sshd completo (timestamp, host, ação, usuário, IP) e de log HTTP (IP, método, endpoint, status).
- **Nível 3 (avançado):** usuário com/sem "invalid user" `for\s+(?:invalid user\s+)?\K\w+`; captura conjunta **IPv4 + IPv6**; SO a partir do User-Agent.
- **Nível 4 (normalização SIEM):** transformação de logs brutos em `src_ip= user= action= status=` com `sed -E`.
- **Nível 5 (detecção SOC):** correlação de **força bruta seguida de sucesso** no mesmo IP (`sort | uniq -c | awk`), equivalente à query SPL `stats count by src_ip | where count > N`.

## Estrutura
`prints/` — um print por nível, mostrando o regex e a saída sobre os logs de exemplo.
