using System;
using System.Activities;
using System.Threading;
using System.Threading.Tasks;
using System.Data;
using GroupeBernard.Keepass.Activities.Properties;
using UiPath.Shared.Activities;
using UiPath.Shared.Activities.Localization;
using System.IO;
using KeePassLib;
using KeePassLib.Serialization;
using System.Diagnostics;
using KeePassLib.Keys;

namespace GroupeBernard.Keepass.Activities
{
    [LocalizedDisplayName(nameof(Resources.Read_DisplayName))]
    [LocalizedDescription(nameof(Resources.Read_Description))]
    public class Read : ContinuableAsyncCodeActivity
    {
        #region Properties

        /// <summary>
        /// If set, continue executing the remaining activities even if the current activity has failed.
        /// </summary>
        [LocalizedCategory(nameof(Resources.Common_Category))]
        [LocalizedDisplayName(nameof(Resources.ContinueOnError_DisplayName))]
        [LocalizedDescription(nameof(Resources.ContinueOnError_Description))]
        public override InArgument<bool> ContinueOnError { get; set; }

        [LocalizedDisplayName(nameof(Resources.Read_PathFile_DisplayName))]
        [LocalizedDescription(nameof(Resources.Read_PathFile_Description))]
        [LocalizedCategory(nameof(Resources.Input_Category))]
        public InArgument<string> PathFile { get; set; }

        [LocalizedDisplayName(nameof(Resources.Read_MasterPassWord_DisplayName))]
        [LocalizedDescription(nameof(Resources.Read_MasterPassWord_Description))]
        [LocalizedCategory(nameof(Resources.Input_Category))]
        public InArgument<string> MasterPassWord { get; set; }

        [LocalizedDisplayName(nameof(Resources.Read_Datatable_DisplayName))]
        [LocalizedDescription(nameof(Resources.Read_Datatable_Description))]
        [LocalizedCategory(nameof(Resources.Output_Category))]
        public OutArgument<DataTable> Datatable { get; set; }

        #endregion


        #region Constructors

        public Read()
        {
        }

        #endregion


        #region Protected Methods

        protected override void CacheMetadata(CodeActivityMetadata metadata)
        {
            if (PathFile == null) metadata.AddValidationError(string.Format(Resources.ValidationValue_Error, nameof(PathFile)));
            if (MasterPassWord == null) metadata.AddValidationError(string.Format(Resources.ValidationValue_Error, nameof(MasterPassWord)));

            base.CacheMetadata(metadata);
        }

        protected override async Task<Action<AsyncCodeActivityContext>> ExecuteAsync(AsyncCodeActivityContext context, CancellationToken cancellationToken)
        {
            // Inputs
            var pathfile = PathFile.Get(context);
            var masterpassword = MasterPassWord.Get(context);
            System.Data.DataTable Data = new DataTable();
            string InfosDebug = "";
            if (File.Exists(pathfile))
            { 
                try
                {
                    InfosDebug += "\nDebut Creation de la datatable\n";
                    Data = new DataTable();
                    Data.Columns.Add("GroupeName", System.Type.GetType("System.String"));
                    Data.Columns.Add("Notes", System.Type.GetType("System.String"));
                    Data.Columns.Add("Login", System.Type.GetType("System.String"));
                    Data.Columns.Add("PassWord", System.Type.GetType("System.String"));
                    Data.Columns.Add("URL", System.Type.GetType("System.String"));
                    Data.Columns.Add("Title", System.Type.GetType("System.String"));
                    InfosDebug += "Fin Creation de la datatable\n";
                    InfosDebug += "Debut manipulation masterKey\n";

                    CompositeKey key = new CompositeKey();
                    KcpPassword pw = new KcpPassword(masterpassword);
                    key.AddUserKey(pw);
                    byte[] pwdata = pw.KeyData.ReadData();
                    byte[] keydata = key.GenerateKey32(pwdata, 6000).ReadData();
                    InfosDebug += "Millieu manipulation masterKey\n";
                    PwDatabase db = new PwDatabase();
                    db.MasterKey = key;
                    InfosDebug += "Fin manipulation masterKey\n";
                    InfosDebug += "Debut ouverture du fichier kdbx\n";
                    KdbxFile kdbx = new KdbxFile(db);
                    kdbx.Load(pathfile, KdbxFormat.Default, null);
                    InfosDebug += "Fin ouverture du fichier kdbx\n";
                    InfosDebug += "Debut lecture rootNode du fichier kdbx\n";

                    var entriesRoots = db.RootGroup.GetEntries(false);
                    int Noligne = 0;
                    foreach (KeePassLib.PwEntry entrie in entriesRoots)
                    {
                        Noligne += 1;
                        InfosDebug += "Debut lecture ligne "+Noligne.ToString()+"/"+ entriesRoots.UCount.ToString()+ " rootNode du fichier kdbx\n";
                        var row = Data.NewRow();
                        row["GroupeName"] = "Root";
                        row["Notes"] = entrie.Strings?.Get(PwDefs.NotesField)?.ReadString() ?? "";
                        row["Login"] = entrie.Strings?.Get(PwDefs.UserNameField)?.ReadString() ?? "";
                        row["PassWord"] = entrie.Strings?.Get(PwDefs.PasswordField)?.ReadString() ?? "";
                        row["URL"] = entrie.Strings?.Get(PwDefs.UrlField)?.ReadString() ?? "";
                        row["Title"] = entrie.Strings?.Get(PwDefs.TitleField)?.ReadString() ?? "";
                        InfosDebug += "Fin lecture ligne " + Noligne.ToString() + " rootNode du fichier kdbx\n";
                        Data.Rows.Add(row);
                        InfosDebug += "Update ligne " + Noligne.ToString() + " rootNode du fichier kdbx\n";
                    }
                    InfosDebug += "Fin lecture rootNode du fichier kdbx\n";

                    InfosDebug += "Debut lecture subNodes du fichier kdbx\n";
                    var groups = db.RootGroup.GetGroups(true);
                    foreach (KeePassLib.PwGroup group in groups)
                    {
                        var entries = group.GetEntries(false);
                        if (entries is null)
                        {
                            continue;
                        }
                        Noligne = 0;
                        foreach (KeePassLib.PwEntry entrie in entries)
                        {
                            Noligne += 1;
                            InfosDebug += "Debut lecture ligne " + Noligne.ToString() + "/" + entries.UCount.ToString() + " "+ group.Name + " du fichier kdbx\n";
                            var row = Data.NewRow();
                            row["GroupeName"] = group.Name;
                            row["Notes"] = entrie.Strings?.Get(PwDefs.NotesField)?.ReadString() ?? "";
                            row["Login"] = entrie.Strings?.Get(PwDefs.UserNameField)?.ReadString() ?? "";
                            row["PassWord"] = entrie.Strings?.Get(PwDefs.PasswordField)?.ReadString() ?? "";
                            row["URL"] = entrie.Strings?.Get(PwDefs.UrlField)?.ReadString() ?? "";
                            row["Title"] = entrie.Strings?.Get(PwDefs.TitleField)?.ReadString() ?? "";
                            InfosDebug += "Fin lecture ligne " + Noligne.ToString() + " " + group.Name + " du fichier kdbx\n";
                            Data.Rows.Add(row);
                            InfosDebug += "Update ligne " + Noligne.ToString() + " " + group.Name + " du fichier kdbx\n";

                        }
                    }
                    InfosDebug += "Fin lecture subNodes du fichier kdbx\n";

                }
                catch (Exception e )
                {

                    throw new Exception(e.Message+InfosDebug);
                }
              
            } else
            {
                throw new Exception("pathfile : '" + pathfile + "' not found");
            }


            // Outputs
            return (ctx) => {
                Datatable.Set(ctx, Data);
            };
        }

        private void MessageBox(string v)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}

