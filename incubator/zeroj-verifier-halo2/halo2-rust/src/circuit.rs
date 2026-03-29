//! Simple multiplier circuit: proves a * b = c without revealing a or b.
//!
//! Uses zcash/halo2 with Pasta curve (Pallas field Fp).
//! Public input: c (the product)
//! Private inputs: a, b (the factors)

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone)]
pub struct MulConfig {
    advice_a: Column<Advice>,
    advice_b: Column<Advice>,
    advice_c: Column<Advice>,
    selector: Selector,
    instance: Column<Instance>,
}

#[derive(Default, Clone)]
pub struct MulCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Circuit<Fp> for MulCircuit {
    type Config = MulConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice_a = meta.advice_column();
        let advice_b = meta.advice_column();
        let advice_c = meta.advice_column();
        let selector = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(advice_c);
        meta.enable_equality(instance);

        meta.create_gate("mul", |vc| {
            let a = vc.query_advice(advice_a, Rotation::cur());
            let b = vc.query_advice(advice_b, Rotation::cur());
            let c = vc.query_advice(advice_c, Rotation::cur());
            let s = vc.query_selector(selector);
            vec![s * (a * b - c)]
        });

        MulConfig { advice_a, advice_b, advice_c, selector, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let c_cell = layouter.assign_region(
            || "mul",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.advice_a, 0, || self.a)?;
                region.assign_advice(|| "b", config.advice_b, 0, || self.b)?;
                let c_val = self.a.and_then(|a| self.b.map(|b| a * b));
                let c_cell = region.assign_advice(|| "c", config.advice_c, 0, || c_val)?;
                Ok(c_cell)
            },
        )?;

        layouter.constrain_instance(c_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}
