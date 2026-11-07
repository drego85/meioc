# Istruzioni per gli agenti

- Ogni novità o modifica deve essere verificata con test adeguati e, quando i test passano, deve essere commitata prima della consegna.
- Esaminare anche le modifiche preesistenti prima di includerle in un commit; preservare i dati locali e i campioni email riservati.
- Eseguire `venv/bin/python -m unittest discover -s tests -v`, la compilazione dei moduli modificati e `git diff --check` prima del commit.
- Aggiungere test di regressione per i difetti funzionali corretti. I test automatici devono poter funzionare senza accesso alla rete.
- Non committare ambienti virtuali, cache, bytecode o email reali. Usare fixture sintetiche nei test.
- Usare commit descrittivi e mirati. Il push remoto richiede una richiesta esplicita.
