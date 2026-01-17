#[macro_export]
macro_rules! asmgen {
    ($($body: tt)*) => {
        // Todo: best practice?
        {
            let mut ops = dynasmrt::aarch64::Assembler::new()?;

            dynasm!(ops
                ; .arch aarch64
                $($body)*
            );

            ops.finalize().unwrap().to_vec()
        }
    };
}
