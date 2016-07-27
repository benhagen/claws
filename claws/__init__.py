
#import netaddr
from netaddr import IPNetwork
from pygments import highlight, lexers, formatters
import colorama
from datetime import datetime
import json

try:
	import geoip2.database
	GEOIP_READER = geoip2.database.Reader("./GeoLite2-City.mmdb")
except:
	GEOIP_READER = None


def cidr_is_within(cidr, cidr_ranges):
	for cidr_range in cidr_ranges:
		if IPNetwork(cidr) in IPNetwork(cidr_range):
			return True
	return False


def cidr_set_optimize(cidr_set):
	output_set = cidr_set.copy()
	for cidr in cidr_set:
		if cidr_set_contains_greater(cidr, cidr_set):
			output_set.remove(cidr)
	return output_set


def cidr_set_contains_greater(test_cidr, cidr_set):
	for cidr in cidr_set:
		if cidr != test_cidr and IPNetwork(test_cidr) in IPNetwork(cidr):
			return True
	return False


class SecurityGroupRule():
	attributes = ["from_port", "to_port", "ip_protocol", "cidr_ip", "group_owner", "group_id"]

	def __init__(self, **kwargs):
		self.__securitygroup__ = None
		for attribute in self.attributes:
			setattr(self, attribute, kwargs.get(attribute, None))
		if self.from_port:
			self.from_port = int(self.from_port)
		if self.to_port:
			self.to_port = int(self.to_port)

	def __eq__(self, other):
		# if self.group_id and other.group_id:
		# 	print "{}\n{}\n\n".format(self, other)
		for attribute in self.attributes:
			if getattr(self, attribute) != getattr(other, attribute):
				return False
		return True

	def to_dict(self):
		output = {}
		for attribute in self.attributes:
			output[attribute] = getattr(self, attribute)
		if self.from_port:
			self.from_port = int(self.from_port)
		if self.to_port:
			self.to_port = int(self.to_port)
		return output

	def summarize(self, colorize=True):
		location = "Unknown Location"
		if GEOIP_READER:
			try:
				response = GEOIP_READER.city(self.cidr_ip.split("/")[0])
			except:
				pass
			else:
				location = "{}, {}, {}".format(response.city.name, response.subdivisions.most_specific.name, response.country.iso_code)
		output = "{: <24} ({}): {: <4} {: >5}-{: <5} {: <18} ({})".format(self.__securitygroup__.group_name, self.__securitygroup__.group_id, self.ip_protocol, self.from_port, self.to_port, self.cidr_ip, location)
		if colorize:
			if self.cidr_ip == "0.0.0.0/0":
				output = "{}{}{}".format(colorama.Fore.RED, output, colorama.Fore.WHITE)
			elif "/32" not in self.cidr_ip:
				output = "{}{}{}".format(colorama.Fore.YELLOW, output, colorama.Fore.WHITE)
		return output

	def __repr__(self):
		return str(self.to_dict())


class SecurityGroupRuleList(list):

	def __init__(self, parent):
		self.__securitygroup__ = parent

	def append(self, other):
		# other = copy(other)
		other.__securitygroup__ = self.__securitygroup__
		return super(SecurityGroupRuleList, self).append(other)


class SecurityGroupClass(object):

	def ip_ingress_count(self, trusted_ranges=[]):
		cidrs = set()
		for rule in self.rules:
			if rule.cidr_ip:
				cidrs.add(rule.cidr_ip)
		cidrs = cidr_set_optimize(cidrs)
		count = 0
		for cidr in cidrs:
			count += len(IPNetwork(cidr))
		return count

	@property
	def rules(self):
		output = SecurityGroupRuleList(self)
		for permission in self.ip_permissions:
			base = {
				"from_port": permission.get('FromPort'),
				"to_port": permission.get('ToPort'),
				"ip_protocol": permission.get('IpProtocol'),
				"cidr_ip": None,
				"group_owner": None,
				"group_id": None
			}
			for ip_range in permission['IpRanges']:
				rule = base.copy()
				rule['cidr_ip'] = ip_range['CidrIp']
				output.append(SecurityGroupRule(**rule))
			for group in permission['UserIdGroupPairs']:
				rule = base.copy()
				rule['group_owner'] = group['UserId']
				rule['group_id'] = group['GroupId']
				output.append(SecurityGroupRule(**rule))
		return output

	def __init__(self, *args, **kwargs):
		super(SecurityGroupClass, self).__init__(*args, **kwargs)


def add_custom_securitygroup_class(base_classes, **kwargs):
	base_classes.insert(0, SecurityGroupClass)


class Ec2ResourceClass(object):

	@property
	def vpc_lookup(self):
		output = {}
		for vpc in self.vpcs.all():
			name = None
			print dir(vpc)
			for tag in vpc.tags:
				if tag['Key'] == "Name":
					name = tag['Value']
			if not name:
				name = vpc.vpc_id
			output[name] = vpc
		return output

	def claws_describe_security_group(self, group_id=None, group_name=None, vpc_id=None, vpc_name=None):
		filters = []
		if vpc_name:
			vpc_id = self.vpc_lookup[vpc_name]
		if group_id:
			filters.append({"Name": "group-id", "Values": [group_id]})
		if group_name:
			filters.append({"Name": "group-name", "Values": [group_name]})
		if vpc_id:
			filters.append({"Name": "vpc-id", "Values": [vpc_id]})
		securitygroups = self.security_groups.filter(Filters=filters).all()
		for securitygroup in securitygroups:
			if securitygroup.vpc_id == vpc_id:
				return securitygroup
		return None

	def __init__(self, *args, **kwargs):
		super(Ec2ResourceClass, self).__init__(*args, **kwargs)


def add_custom_ec2resource_class(base_classes, **kwargs):
	base_classes.insert(0, Ec2ResourceClass)


def clawsify(session):
	session.events.register('creating-resource-class.ec2', add_custom_ec2resource_class)
	session.events.register('creating-resource-class.ec2.SecurityGroup', add_custom_securitygroup_class)
	return session


def json_serializer(obj):
	if isinstance(obj, datetime):
		return int((obj.replace(tzinfo=None) - datetime(1970, 1, 1)).total_seconds())
	if isinstance(obj, set):
		return list(obj)


def jd(dict):
	formatted_json = json.dumps(dict, indent=4, sort_keys=True, default=json_serializer)
	colorful_json = highlight(unicode(formatted_json, 'UTF-8'), lexers.JsonLexer(), formatters.TerminalFormatter())
	print colorful_json


def get_tag(tag_name, aws_dict):
	if isinstance(aws_dict, dict):
		for tag in aws_dict.get('Tags', []):
			if tag['Key'] == tag_name:
				return tag['Value']
	elif getattr(aws_dict, "tags"):
		for tag in aws_dict.tags:
			if tag['Key'] == tag_name:
				return tag['Value']
	return None
