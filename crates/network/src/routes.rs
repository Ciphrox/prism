use std::net::Ipv4Addr;
use std::thread;

use anyhow::{Result, anyhow};
use futures_util::TryStreamExt;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::new_connection;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::rule::RuleAction;
use rtnetlink::packet_route::rule::{RuleAttribute, RuleMessage};

pub struct PolicyRoute {
    oif: u32,
}

impl PolicyRoute {
    const TABLE: u32 = 777;
    const PRIORITY: u32 = 7777;

    pub async fn install(ifname: &str) -> Result<Self> {
        let (conn, handle, _) = new_connection()?;
        tokio::spawn(conn);

        let mut links = handle.link().get().match_name(ifname.to_string()).execute();

        let link = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow!("interface {ifname} not found"))?;
        let oif = link.header.index;

        handle
            .rule()
            .add()
            .v4()
            .fw_mark(0xC0DE007)
            .priority(7760)
            .table_id(254)
            .action(RuleAction::ToTable)
            .execute()
            .await?;

        handle
            .rule()
            .add()
            .v4()
            .table_id(Self::TABLE)
            .priority(Self::PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await?;

        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(oif)
            .table_id(Self::TABLE)
            .build();

        handle.route().add(route).execute().await?;

        Ok(Self { oif })
    }
}

impl Drop for PolicyRoute {
    fn drop(&mut self) {
        let oif = self.oif;

        let _ = thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                let _ = rt.block_on(delete_route_and_route(oif));
            }
        })
        .join();
    }
}

async fn delete_route_and_route(oif: u32) -> Result<()> {
    let (conn, handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut fwmark_rule = RuleMessage::default();
    fwmark_rule.header.family = AddressFamily::Inet;
    fwmark_rule.header.table = 0;
    fwmark_rule
        .attributes
        .push(RuleAttribute::FwMark(0xC0DE007));
    fwmark_rule.attributes.push(RuleAttribute::Priority(7760));

    handle.rule().del(fwmark_rule).execute().await?;

    let mut rule = RuleMessage::default();
    rule.header.family = AddressFamily::Inet;
    rule.header.table = 0;
    rule.attributes
        .push(RuleAttribute::Table(PolicyRoute::TABLE));
    rule.attributes
        .push(RuleAttribute::Priority(PolicyRoute::PRIORITY));

    handle.rule().del(rule).execute().await?;

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(oif)
        .table_id(PolicyRoute::TABLE)
        .build();

    handle.route().del(route).execute().await?;

    Ok(())
}
