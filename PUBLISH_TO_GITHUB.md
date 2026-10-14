# Publish TraceLock to GitHub

The repository files are ready. To publish them as a **new public repository** under `Rizwan1821`:

1. Open <https://github.com/new> and sign in as `Rizwan1821`.
2. Set **Repository name** to `TraceLock` and choose **Public**.
3. Do not initialize it with a README, `.gitignore`, or license; all three are already included here.
4. Extract `TraceLock_Java_Cybersecurity_Project.zip`. Open a terminal inside the extracted `TraceLock` folder (the folder containing `pom.xml`).
5. Run these commands:

```powershell
git init -b main
git add .
git commit -m "Initial commit: TraceLock Java security log analyzer"
git remote add origin https://github.com/Rizwan1821/TraceLock.git
git push -u origin main
```

Git may open a browser sign-in flow. Do not paste a password or token into this guide or commit one into the repository.

If `TraceLock` is unavailable as a repository name, choose `TraceLock-Java-Security-Analyzer` and update the remote URL in the final command sequence accordingly.

## Verify after publishing

Open <https://github.com/Rizwan1821/TraceLock>. The source tree, README and workflow should appear. Under **Actions**, check the `Java CI` workflow after it runs. It runs `mvn verify` on pushes and pull requests.

## Run locally first

```powershell
java -version
mvn -version
mvn clean verify
mvn package
java -jar target/tracelock-1.0.0.jar data/sample-events.csv
```
