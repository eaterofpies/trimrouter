use vergen_gitcl::{Build, Emitter, Gitcl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gitcl = Gitcl::all_git();
    let build = Build::all_build();
    Emitter::default()
        .add_instructions(&gitcl)?
        .add_instructions(&build)?
        .emit()?;
    Ok(())
}
