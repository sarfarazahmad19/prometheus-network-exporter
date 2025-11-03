from enum import Enum
from ipaddress import IPv4Address
from typing import Dict

from pydantic import BaseModel, ConfigDict, ValidationInfo, computed_field, field_validator


class CiscoInterfaceSide(Enum):
    A = "a"
    B = "b"


class CiscoInterfaceType(Enum):
    Service = "service"
    Member = "member"


class CiscoInterface(BaseModel):
    # Ignore extra args
    model_config = ConfigDict(extra="ignore")

    description: str
    interface: str
    ip_address: IPv4Address

    @field_validator("description")
    @classmethod
    def descr_validator(cls, v: str, info: ValidationInfo) -> str:
        assert dict(i.split(":") for i in v.split("/")[1:-1])
        return v

    @computed_field
    @property
    def description_structured(self) -> Dict:
        # splits "#/env:uat/side:a/type:service/name:transit/"
        return dict(i.split(":") for i in self.description.split("/")[1:-1])

    @computed_field
    @property
    def type(self) -> CiscoInterfaceType:
        return CiscoInterfaceType(self.description_structured["type"])

    @computed_field
    @property
    def side(self) -> CiscoInterfaceSide:
        return CiscoInterfaceSide(self.description_structured["side"])

    @computed_field
    @property
    def name(self) -> str:
        return self.description_structured["name"]

    vrf = name

    @computed_field
    @property
    def gre_remote_address(self) -> IPv4Address:
        # remote ends of the tunnel are always one-higher than local address
        return self.ip_address + 1
