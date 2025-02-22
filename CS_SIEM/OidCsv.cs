namespace CS_SIEM;

/// <summary>
/// Represents an OID (Object Identifier) entry in CSV format, containing various properties
/// such as name, identifier, data type, permissions, class, node type, and description.
/// this is used to get Data from a CSV
/// </summary>
public class OidCsv
{
    /// <summary>
    /// Gets or sets the name of the object.
    /// </summary>
    public string  OBJECT_NAME { get; set; }

    /// <summary>
    /// Gets or sets the object identifier for the SNMP object.
    /// </summary>
    public string OBJECT_IDENTIFIER { get; set; }

    /// <summary>
    /// Gets or sets the data type of the object.
    /// </summary>
    public string OBJECT_DATA_TYPE { get; set; }

    /// <summary>
    /// Gets or sets the permissions associated with the object.
    /// </summary>
    public string OBJECT_PERMISSIONS { get; set; }
    /// <summary>
    /// Gets or sets the class of the object.
    /// </summary>
    public string OBJECT_CLASS { get; set; }

    /// <summary>
    /// Gets or sets the node type of the object.
    /// </summary>
    public string OBJECT_NODE_TYPE { get; set; }

    /// <summary>
    /// Gets or sets the description of the object.
    /// </summary>
    public string OBJECT_DESCRIPTION { get; set; }
}