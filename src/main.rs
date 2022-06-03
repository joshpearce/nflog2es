use clap::{Arg, Command};
use std::fmt::Write;

fn log_callback(msg: nflog::Message) {
    println!("Packet received\n");
    println!(
        " -> uid: {}, gid: {}",
        msg.get_uid().unwrap_or(0xffff),
        msg.get_gid().unwrap_or(0xffff)
    );
    println!(" -> prefix: {}", msg.get_prefix().to_string_lossy());
    println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));

    let payload_data = msg.get_payload();
    let mut s = String::new();
    for &byte in payload_data {
        write!(&mut s, "{:02X} ", byte).unwrap();
    }
    println!("{}", s);

    let hwaddr = msg.get_packet_hw().unwrap_or_default();
    println!("{}", hwaddr);

    println!("XML\n{}", msg.as_xml_str(nflog::XMLFormat::All).unwrap());
}

fn main() {
    let matches = Command::new("nflog2es")
        .version("0.1.0")
        .about("Pushes Netfilter logs to ElasticSearch")
        .arg(
            Arg::new("es_host")
                .takes_value(true)
                .value_name("ES_HOST")
                .long("es_host")
                .env("ES_HOST")
                .required(false)
                .help("ElasticSearch URL"),
        )
        .arg(
            Arg::new("es_user")
                .takes_value(true)
                .value_name("ES_USER")
                .long("es_user")
                .short('u')
                .env("ES_USER")
                .required(false)
                .help("ElasticSearch username"),
        )
        .arg(
            Arg::new("es_pass")
                .takes_value(true)
                .value_name("ES_PASS")
                .long("es_pass")
                .short('p')
                .env("ES_PASS")
                .required(false)
                .help("ElasticSearch password"),
        )
        .arg(
            Arg::new("group")
                .takes_value(true)
                .value_name("GROUP")
                .long("group")
                .short('g')
                .required(true)
                .multiple_occurrences(true)
                .help("nflog group number"),
        )
        .get_matches();
    //let es_host: &str = matches.value_of("es_host").unwrap();
    //let es_user: &str = matches.value_of("es_user").unwrap();
    //let es_pass: &str = matches.value_of("es_pass").unwrap();
    let groups: Vec<u16> = matches.values_of_t("group").unwrap();

    let queue = nflog::Queue::open().unwrap();

    println!("nflog example program: print packets metadata");

    let _ = queue.unbind(libc::AF_INET); // ignore result, failure is not critical here

    queue.bind(libc::AF_INET).unwrap();

    let mut log_groups = Vec::new();

    for g in &groups {
        let mut group = queue.bind_group(*g).unwrap();

        group.set_mode(nflog::CopyMode::Packet, 0xffff);
        //group.set_nlbufsiz(0xffff);
        //group.set_timeout(1500);

        group.set_flags(nflog::Flags::Sequence);

        group.set_callback(Box::new(log_callback));
        log_groups.push(group)
    }
    queue.run_loop();
}
