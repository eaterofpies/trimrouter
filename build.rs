use vergen_gitcl::{BuildBuilder, Emitter, GitclBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Emitter::default()
        .add_instructions(&GitclBuilder::default().sha(true).build()?)?
        .add_instructions(&BuildBuilder::default().build_timestamp(true).build()?)?
        .emit()?;
    Ok(())
}
