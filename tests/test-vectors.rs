use color_eyre::eyre::Result;
use libtest_mimic::{Arguments, Trial};

#[path = "test-vectors/ecvrf.rs"]
mod ecvrf;

pub trait TestVector: serde::de::DeserializeOwned {
    fn file_names() -> Vec<&'static str>;
    fn execute(self) -> Result<()>;
    fn name(&self) -> String;

    fn collect_tests() -> Result<Vec<Trial>>
    where
        Self: Sized + Send + 'static,
    {
        let mut tests: Vec<Trial> = vec![];
        for file in Self::file_names() {
            let mut path = std::path::PathBuf::from("tests/test-vectors/test-vector-data");
            path.push(file);
            let file = std::fs::File::open(path)?;
            let reader = std::io::BufReader::new(file);
            let test_instances: Vec<Self> = serde_json::from_reader(reader)?;
            tests.extend(test_instances.into_iter().map(|test| {
                Trial::test(test.name(), move || {
                    test.execute().unwrap();

                    Ok(())
                })
                .with_kind("rfc9381-test-vector")
            }));
        }

        tests.sort_unstable_by(|a, b| a.name().cmp(b.name()));

        Ok(tests)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];
    tests.append(&mut ecvrf::EcVrfTestVector::collect_tests()?);

    libtest_mimic::run(&args, tests).exit_if_failed();
    Ok(())
}
