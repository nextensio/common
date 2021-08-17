use super::*;
use common::Transport;
use core::time::Duration;

#[test]
fn loopback() {
    let  pool = Arc::new(Pool::new(100, || Vec::with_capacity(2048)));
    let mut pipe = Pipe::new_client(r"\\.\pipe\nextensio".to_string(), true, pool.clone()).unwrap();

    let mut events = mio::Events::with_capacity(2048);
    let mut poll = match mio::Poll::new() {
        Err(e) => panic!("Cannot create a poller {:?}", e),
        Ok(p) => p,
    };
    if let Err(e) = pipe.event_register(Token(0), &mut poll, RegType::Reg) {
        panic!("Cannot register pipe {}", e);
    }
    match pipe.dial() {
        Err(e) => match e.code {
            common::NxtErr::EWOULDBLOCK => {
            // Ok
            },
            _ => panic!("Error dialling, {}", e),
        },
        Ok(_) => (),
    }
    loop {        
        match poll.poll(&mut events, None) {
            Err(e) => println!("Error polling {:?}, retrying", e),
            Ok(_) => {}
        }
        println!("Got event");
        for event in events.iter() {
            match event.token() {
                Token(0) => {
                    if event.is_readable() {
                        println!("Got readable event");
                        if let Ok(r) = pipe.read()  {
                            let (s, b) = r;
                            println!("Got pkt {} / {}", s, b.bufs[0].len());
                            if let Ok(_) = pipe.write(s, b) {
                                println!("Wrote pkt")
                            } else {
                                println!("Cannot write pkt");
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                }
                _ => (),
            }
        }
    }
}