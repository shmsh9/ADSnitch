use tokio_postgres::{Client, Error, NoTls, };
use crate::auth_event::AuthEvent;
use crate::config::Config;

pub struct DataBase{
    client : Client
}

impl DataBase {
    pub async fn new(config: Config) -> Result<DataBase,Error> {
        let (client, connection) = tokio_postgres::connect(
            &format!("host={} user={} password={}", 
                config.database_server, config.database_user, config.database_password),
                NoTls
            )
            .await?;
        tokio::spawn(connection);
        return Ok(
            DataBase { 
                client: client
            }
        );
    }
    pub async fn send_auth_event(&self, event: AuthEvent) -> Result<(), Error> {
        self.client.execute(event.sql_insert(),
        &[
                &event.target_user_name,
                &event.workstation_name, 
                &event.target_domain_name, 
                &event.service_name, 
                &event.ip_address, 
                &event.datetime.timestamp_millis(), 
                &event.auth_type, 
                &event.status, 
                &event.successfull
            ]
        ).await?;
        Ok(())
    }
}
