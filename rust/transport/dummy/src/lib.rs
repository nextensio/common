use std::time::Duration;

use common::{NxtBufs, NxtErr, NxtError};

pub struct Dummy {
    closed: bool,
}

impl Default for Dummy {
    fn default() -> Self {
        Dummy { closed: true }
    }
}

impl common::Transport for Dummy {
    fn dial(&mut self) -> Result<(), NxtError> {
        Ok(())
    }

    fn new_stream(&mut self) -> u64 {
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        Ok(())
    }

    fn is_closed(&self, _: u64) -> bool {
        self.closed
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        return Err(NxtError {
            code: NxtErr::CONNECTION,
            detail: "dummy trait".to_string(),
        });
    }

    fn write(&mut self, _: u64, _: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        return Err((
            None,
            NxtError {
                code: NxtErr::CONNECTION,
                detail: "dummy trait".to_string(),
            },
        ));
    }
}
